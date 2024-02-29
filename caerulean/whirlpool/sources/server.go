package main

import (
	"context"
	"crypto/cipher"
	"encoding/hex"
	"main/crypto"
	"main/generated"
	"main/users"
	"main/utils"
	"strings"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

const VERSION = "0.0.1"

type WhirlpoolServer struct {
	generated.UnimplementedWhirlpoolViridianServer

	nodeOwnerPayload    string
	nodeViridianPayload string

	viridians  users.ViridianDict
	privateKey cipher.AEAD
	base       context.Context
}

func createWhirlpoolServer(ctx context.Context) *WhirlpoolServer {
	nodeOwnerPayload := utils.GetEnv("SEASIDE_PAYLOAD_OWNER")
	nodeViridianPayload := utils.GetEnv("SEASIDE_PAYLOAD_VIRIDIAN")

	privateKey, err := crypto.GenerateCipher()
	if err != nil {
		logrus.Fatalf("error creating server private key: %v", err)
	}

	return &WhirlpoolServer{
		nodeOwnerPayload:    nodeOwnerPayload,
		nodeViridianPayload: nodeViridianPayload,
		viridians:           *users.NewViridianDict(ctx),
		privateKey:          privateKey,
		base:                ctx,
	}
}

func (server *WhirlpoolServer) destroyWhirlpoolServer() {
	server.viridians.Clear()
}

func (server *WhirlpoolServer) Authenticate(ctx context.Context, request *generated.WhirlpoolAuthenticationRequest) (*generated.WhirlpoolAuthenticationResponse, error) {
	// Check node owner key
	if request.Payload != server.nodeOwnerPayload && request.Payload != server.nodeViridianPayload {
		return nil, status.Error(codes.PermissionDenied, "wrong payload value")
	}

	// Create and marshall user token
	token := &generated.UserToken{
		Uid:        request.Uid,
		Session:    request.Session,
		Privileged: request.Payload == server.nodeOwnerPayload,
	}
	marshToken, err := proto.Marshal(token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error marshalling token: %v", err)
	}

	// Encrypt token
	tokenData, err := crypto.Encrypt(marshToken, server.privateKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error encrypting token: %v", err)
	}

	// Create and marshall response
	grpc.SetTrailer(ctx, metadata.Pairs("tail", hex.EncodeToString(utils.GenerateReliableTail())))
	return &generated.WhirlpoolAuthenticationResponse{
		Token: tokenData,
	}, nil
}

func (server *WhirlpoolServer) Connect(ctx context.Context, request *generated.ControlConnectionRequest) (*generated.ControlConnectionResponse, error) {
	address, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.DataLoss, "error identifying source IP address")
	}

	remoteAddress, _, err := utils.GetIPAndPortFromAddress(address.Addr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error parsing gateway IP address: %v", err)
	}

	// Check viridian version
	if strings.Split(VERSION, ".")[0] != strings.Split(request.Version, ".")[0] {
		return nil, status.Error(codes.FailedPrecondition, "major versions do not match")
	}

	// Check if token is not null
	if request.Token == nil {
		return nil, status.Error(codes.InvalidArgument, "user token is null")
	}

	// Decode token
	tokenBytes, err := crypto.Decrypt(request.Token, server.privateKey)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "error decrypting token")
	}

	// Unmarshall token datastructure
	token := &generated.UserToken{}
	err = proto.Unmarshal(tokenBytes, token)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "error unmarshalling token")
	}

	if request.Payload != nil {
		token.Privileged = token.Privileged || (*request.Payload == server.nodeOwnerPayload)
	}

	userID, err := server.viridians.Add(server.base, token, request.Address, remoteAddress, uint16(request.Port))
	if err != nil {
		return nil, err
	}

	logrus.Infof("User %d (uid: %s, privileged: %t) connected", *userID, token.Uid, token.Privileged)

	grpc.SetTrailer(ctx, metadata.Pairs("tail", hex.EncodeToString(utils.GenerateReliableTail())))
	return &generated.ControlConnectionResponse{
		UserID: int32(*userID),
	}, nil
}

func (server *WhirlpoolServer) Healthcheck(ctx context.Context, request *generated.ControlHealthcheck) (*emptypb.Empty, error) {
	userID := uint16(request.UserID)
	viridian, ok := server.viridians.Get(userID)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "user not connected: %d", userID)
	}

	nextIn := request.NextIn
	logrus.Infof("Healthcheck from user %s: %d, next in %d", viridian.UID, userID, nextIn)

	err := server.viridians.Update(userID, nextIn)
	if err != nil {
		return nil, err
	}

	grpc.SetTrailer(ctx, metadata.Pairs("tail", hex.EncodeToString(utils.GenerateReliableTail())))
	return &emptypb.Empty{}, nil
}

func (server *WhirlpoolServer) Exception(ctx context.Context, request *generated.ControlException) (*emptypb.Empty, error) {
	userID := uint16(request.UserID)
	viridian, ok := server.viridians.Get(userID)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "user not connected: %d", userID)
	}

	if request.Status == generated.ControlExceptionStatus_TERMINATION {
		logrus.Infof("Disconnecting user %s: %d", viridian.UID, userID)
	} else if request.Message != nil {
		logrus.Infof("Aborting user connection, user %s: %d, message: %s", viridian.UID, userID, *request.Message)
	} else {
		logrus.Infof("Aborting user connection, user %s: %d, reason unknown!", viridian.UID, userID)
	}

	server.viridians.Delete(userID, false)

	grpc.SetTrailer(ctx, metadata.Pairs("tail", hex.EncodeToString(utils.GenerateReliableTail())))
	return &emptypb.Empty{}, nil
}
