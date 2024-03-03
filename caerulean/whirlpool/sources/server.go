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

// Current Whirlpool distribution version.
const VERSION = "0.0.1"

// Whirlpool server structure.
// Extends from generated gRPC Whirlpool server API.
// Contains all the data required for server execution.
type WhirlpoolServer struct {
	generated.UnimplementedWhirlpoolViridianServer

	// Authentication string for node owner (administrator).
	nodeOwnerPayload string

	// Authentication string for node user (viridian).
	nodeViridianPayload string

	// Viridians dictionary, contains all the currently connected viridians.
	viridians users.ViridianDict

	// Private node AEAD: used for authentication token encryption.
	// TODO: change it once in a while.
	privateKey cipher.AEAD

	// Server context, used as a base context for viridian port listeners.
	base context.Context
}

// Create Whirlpool server.
// Read payloads from environment variables, generate private key.
// Accept context for viridian listener base.
// Return Whirlpool server pointer.
func createWhirlpoolServer(ctx context.Context) *WhirlpoolServer {
	// Read server payloads from environment
	nodeOwnerPayload := utils.GetEnv("SEASIDE_PAYLOAD_OWNER")
	nodeViridianPayload := utils.GetEnv("SEASIDE_PAYLOAD_VIRIDIAN")

	// Generate private node cipher
	privateKey, err := crypto.GenerateCipher()
	if err != nil {
		logrus.Fatalf("error creating server private key: %v", err)
	}

	// Return Whirlpool server pointer
	return &WhirlpoolServer{
		nodeOwnerPayload:    nodeOwnerPayload,
		nodeViridianPayload: nodeViridianPayload,
		viridians:           *users.NewViridianDict(ctx),
		privateKey:          privateKey,
		base:                ctx,
	}
}

// Destroy Whirlpool server.
// Gracefully srops all the viridian listeners.
// Should be applied for WhirlpoolServer object.
func (server *WhirlpoolServer) destroyWhirlpoolServer() {
	server.viridians.Clear()
}

// Authenticate viridian.
// Check payload values, create user token and encrypt it with private key.
// Send the token to user.
// Should be applied for WhirlpoolServer object.
// Accept context and authentication request.
// Return authentication response and nil if authentication successful, otherwise nil and error.
func (server *WhirlpoolServer) Authenticate(ctx context.Context, request *generated.WhirlpoolAuthenticationRequest) (*generated.WhirlpoolAuthenticationResponse, error) {
	// Check node owner or viridian payload
	if request.Payload != server.nodeOwnerPayload && request.Payload != server.nodeViridianPayload {
		return nil, status.Error(codes.PermissionDenied, "wrong payload value")
	}

	// Create and marshall user token
	token := &generated.UserToken{
		Uid:        request.Uid,
		Session:    request.Session,
		Privileged: request.Payload == server.nodeOwnerPayload,
	}
	logrus.Infof("User %s (privileged: %t) autnenticated", token.Uid, token.Privileged)
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

// Connect viridian.
// Receive all the request parameters required, check version, decrypt and parse token.
// Add viridian to the viridian dictionary if everything went fine.
// Should be applied for WhirlpoolServer object.
// Accept context and connection request.
// Return connection response and nil if connection successful, otherwise nil and error.
func (server *WhirlpoolServer) Connect(ctx context.Context, request *generated.ControlConnectionRequest) (*generated.ControlConnectionResponse, error) {
	// Get viridian "gateway": the IP address the packages can be forwarded through
	address, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.DataLoss, "error identifying source IP address")
	}

	// Parse viridian gateway address and port
	remoteAddress, _, err := utils.GetIPAndPortFromAddress(address.Addr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error parsing gateway IP address: %v", err)
	}

	// Check viridian version (major)
	if strings.Split(VERSION, ".")[0] != strings.Split(request.Version, ".")[0] {
		return nil, status.Error(codes.FailedPrecondition, "major versions do not match")
	}

	// Check if token is not null
	if request.Token == nil {
		return nil, status.Error(codes.InvalidArgument, "user token is null")
	}

	// Decrypt token
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

	// Make viridian privileged if it passed owner payload
	if request.Payload != nil {
		token.Privileged = token.Privileged || (*request.Payload == server.nodeOwnerPayload)
	}

	// Add viridian to the dictionary
	userID, err := server.viridians.Add(server.base, token, request.Address, remoteAddress, uint16(request.Port))
	if err != nil {
		return nil, err
	}

	// Log and return connection response
	logrus.Infof("User %d (uid: %s, privileged: %t) connected", *userID, token.Uid, token.Privileged)
	grpc.SetTrailer(ctx, metadata.Pairs("tail", hex.EncodeToString(utils.GenerateReliableTail())))
	return &generated.ControlConnectionResponse{
		UserID: int32(*userID),
	}, nil
}

// Perform healthcheck.
// Helathchecks should happen from time to time for the connected viridians.
// If no healthcheck happens in a while, viridian will be removed.
// Should be applied for WhirlpoolServer object.
// Accept context and healthcheck request.
// Return empty response and nil if healthcheck successful, otherwise nil and error.
func (server *WhirlpoolServer) Healthcheck(ctx context.Context, request *generated.ControlHealthcheck) (*emptypb.Empty, error) {
	// Get connected viridian by ID
	userID := uint16(request.UserID)
	viridian, ok := server.viridians.Get(userID)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "user not connected: %d", userID)
	}

	// Get next healthcheck timeout
	nextIn := request.NextIn
	logrus.Infof("Healthcheck from user %s: %d, next in %d", viridian.UID, userID, nextIn)

	// Update the viridian deletion timer
	err := server.viridians.Update(userID, nextIn)
	if err != nil {
		return nil, err
	}

	// Return empty response
	grpc.SetTrailer(ctx, metadata.Pairs("tail", hex.EncodeToString(utils.GenerateReliableTail())))
	return &emptypb.Empty{}, nil
}

// Process exception.
// React to viridian reporting an exception.
// Viridian will be removed, an appropriate response message will be sent.
// Should be applied for WhirlpoolServer object.
// Accept context and exception request.
// Return empty response and nil if exception hendling successful, otherwise nil and error.
func (server *WhirlpoolServer) Exception(ctx context.Context, request *generated.ControlException) (*emptypb.Empty, error) {
	// Get connected viridian by ID
	userID := uint16(request.UserID)
	viridian, ok := server.viridians.Get(userID)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "user not connected: %d", userID)
	}

	// Check exception status and react according to it
	if request.Status == generated.ControlExceptionStatus_TERMINATION {
		logrus.Infof("Disconnecting user %s: %d", viridian.UID, userID)
	} else if request.Message != nil {
		logrus.Infof("Aborting user connection, user %s: %d, message: %s", viridian.UID, userID, *request.Message)
	} else {
		logrus.Infof("Aborting user connection, user %s: %d, reason unknown!", viridian.UID, userID)
	}

	// Remove viridian and return empty response
	server.viridians.Delete(userID, false)
	grpc.SetTrailer(ctx, metadata.Pairs("tail", hex.EncodeToString(utils.GenerateReliableTail())))
	return &emptypb.Empty{}, nil
}
