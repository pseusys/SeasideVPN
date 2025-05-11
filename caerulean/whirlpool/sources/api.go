package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"main/crypto"
	"main/generated"
	"main/utils"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pseusys/betterbuf"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	DEFAULT_CERTIFICATES_PATH = "certificates"

	DEFAULT_ADMIN_KEYS           = ""
	DEFAULT_ADMIN_TOKEN_TIMEOUT  = 24 * 365
	DEFAULT_GRPC_MAX_TAIL_LENGTH = 256
)

var (
	NODE_OWNER_API_KEY  = utils.RequireEnv("SEASIDE_API_KEY_OWNER")
	NODE_ADMIN_API_KEYS = strings.Split(utils.GetEnv("SEASIDE_API_KEY_ADMIN", DEFAULT_ADMIN_KEYS), ":")

	ADMIN_TOKEN_TIMEOUT  = utils.GetIntEnv("SEASIDE_ADMIN_TOKEN_TIMEOUT", DEFAULT_ADMIN_TOKEN_TIMEOUT, 32)
	GRPC_MAX_TAIL_LENGTH = uint(utils.GetIntEnv("SEASIDE_GRPC_MAX_TAIL_LENGTH", DEFAULT_GRPC_MAX_TAIL_LENGTH, 32))
)

// Metaserver structure.
// Contains gRPC server and whirlpool server, also includes connection listener.
type APIServer struct {
	// General purpose gRPC server.
	grpcServer *grpc.Server

	// gRPC connection listener.
	listener net.Listener
}

// Whirlpool server structure.
// Extends from generated gRPC Whirlpool server API.
// Contains all the data required for server execution.
type WhirlpoolServer struct {
	generated.UnimplementedWhirlpoolViridianServer

	portPort    int32
	typhoonPort int32
}

// Load TLS credentials from files.
// Certificates are expected to be in `certificates/cert.crt` and `certificates/cert.key` files.
// Certificates should be valid and contain `subjectAltName` for the current SEASIDE_ADDRESS.
func loadTLSCredentials() (credentials.TransportCredentials, error) {
	// Format server key and certificate paths
	certificatesPath := utils.GetEnv("SEASIDE_CERTIFICATE_PATH", DEFAULT_CERTIFICATES_PATH)
	keyPath := fmt.Sprintf("%s/cert.key", certificatesPath)
	certPath := fmt.Sprintf("%s/cert.crt", certificatesPath)

	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading certificates: %v", err)
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
	}

	// Return credentials
	return credentials.NewTLS(config), nil
}

func NewAPIServer(intAddress string, portPort, typhoonPort int32) (*APIServer, error) {
	// Create whirlpool server
	whirlpoolServer := WhirlpoolServer{
		portPort:    portPort,
		typhoonPort: typhoonPort,
	}

	// Create TCP listener for gRPC connections
	listener, err := net.Listen("tcp", intAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %v", err)
	}

	// Load TLS credentials from files
	credentials, err := loadTLSCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials: %v", err)
	}

	// Create and start gRPC server
	grpcServer := grpc.NewServer(grpc.Creds(credentials))
	generated.RegisterWhirlpoolViridianServer(grpcServer, &whirlpoolServer)

	return &APIServer{
		grpcServer: grpcServer,
		listener:   listener,
	}, nil
}

// Run metaserver.
// Accept gRPC server and TCP connection listener.
func (server *APIServer) Start(ctx context.Context, wg *sync.WaitGroup, errorChan chan error) {
	defer wg.Done()

	logrus.Infof("Starting gRPC server on address: %v", server.listener.Addr())
	if err := server.grpcServer.Serve(server.listener); err != nil {
		select {
		case <-ctx.Done():
			return
		default:
			errorChan <- fmt.Errorf("failed to serve: %v", err)
		}
	}
}

// Stop metaserver.
// Should be applied for MetaServer object.
// Accept metaserver object pointer.
// Destroy gRPC and Whirlpool server, also close TCP listener.
func (server *APIServer) Stop() {
	server.grpcServer.GracefulStop()
}

// Authenticate viridian.
// Check payload values, create user token and encrypt it with private key.
// Send the token to user.
// Should be applied for WhirlpoolServer object.
// Accept context and authentication request.
// Return authentication response and nil if authentication successful, otherwise nil and error.
func (server *WhirlpoolServer) Authenticate(ctx context.Context, request *generated.WhirlpoolAuthenticationRequest) (*generated.WhirlpoolAuthenticationResponse, error) {
	// Check node owner or viridian payload
	if request.ApiKey != NODE_OWNER_API_KEY && !slices.Contains(NODE_ADMIN_API_KEYS, request.ApiKey) {
		return nil, status.Error(codes.PermissionDenied, "wrong payload value")
	}

	// Create and marshall user token (will be valid for 10 years for non-privileged users)
	token := &generated.UserToken{
		Name:         request.Name,
		Identifier:   request.Identifier,
		IsAdmin:      true,
		Subscription: timestamppb.New(time.Now().Add(time.Hour * time.Duration(ADMIN_TOKEN_TIMEOUT))),
	}
	logrus.Infof("User %s (id: %s) autnenticated", token.Name, token.Identifier)
	marshToken, err := proto.Marshal(token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error marshalling token: %v", err)
	}

	// Encrypt token
	tokenBuffer := betterbuf.NewBufferFromCapacityEnsured(marshToken, crypto.NonceSize, crypto.MacSize)
	tokenData, err := crypto.SERVER_KEY.Encrypt(tokenBuffer, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error encrypting token: %v", err)
	}

	// Create and marshall response
	grpc.SetTrailer(ctx, metadata.Pairs("seaside-tail-bin", hex.EncodeToString(utils.GenerateReliableTail(GRPC_MAX_TAIL_LENGTH).Slice())))
	return &generated.WhirlpoolAuthenticationResponse{
		Token:       tokenData.Slice(),
		PublicKey:   crypto.PRIVATE_KEY.PublicKey().Slice(),
		PortPort:    server.portPort,
		TyphoonPort: server.typhoonPort,
	}, nil
}
