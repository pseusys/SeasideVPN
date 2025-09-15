package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"main/crypto"
	"main/generated"
	"main/utils"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/pseusys/betterbuf"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	DEFAULT_CERTIFICATES_PATH = "certificates"
	DEFAULT_SUGGESTED_DNS     = "8.8.8.8"

	DEFAULT_ADMIN_KEYS           = ""
	DEFAULT_GRPC_MAX_TAIL_LENGTH = 256
)

var (
	NODE_OWNER_API_KEY  = utils.RequireEnv("SEASIDE_API_KEY_OWNER")
	NODE_ADMIN_API_KEYS = strings.Split(utils.GetEnv("SEASIDE_API_KEY_ADMIN", DEFAULT_ADMIN_KEYS), ":")

	GRPC_MAX_TAIL_LENGTH = uint(utils.GetIntEnv("SEASIDE_GRPC_MAX_TAIL_LENGTH", DEFAULT_GRPC_MAX_TAIL_LENGTH, 32))
	SUGGESTED_DNS_SERVER = utils.GetEnv("SEASIDE_SUGGESTED_DNS", DEFAULT_SUGGESTED_DNS)
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

	address     string
	portPort    uint16
	typhoonPort uint16
}

// Load TLS credentials from files.
// Certificates are expected to be in `certificates/cert.crt` and `certificates/cert.key` files.
// Certificates should be valid and contain `subjectAltName` for the current SEASIDE_ADDRESS.
func loadTLSCredentials() (credentials.TransportCredentials, error) {
	// Receive certificate path
	certificatesPath := utils.GetEnv("SEASIDE_CERTIFICATE_PATH", DEFAULT_CERTIFICATES_PATH)

	// Format certificate authority path
	CAPath := fmt.Sprintf("%s/rootCA.crt", certificatesPath)

	// Load certificate authority certificate
	caCertPEM, err := os.ReadFile(CAPath)
	if err != nil {
		log.Fatalf("error reading client CA certificate: %v", err)
	}

	// Load certificate authority pool and add current CA certificate
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		log.Fatal("error adding client CA certificate")
	}

	// Format certificate paths
	keyPath := fmt.Sprintf("%s/cert.key", certificatesPath)
	certPath := fmt.Sprintf("%s/cert.crt", certificatesPath)

	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading certificates: %v", err)
	}

	// Create the credentials and return it
	config := &tls.Config{
		ClientCAs:    certPool,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// Return credentials
	return credentials.NewTLS(config), nil
}

func NewAPIServer(intAddress string, portPort, typhoonPort uint16) (*APIServer, error) {
	// Create whirlpool server
	whirlpoolServer := WhirlpoolServer{
		address:     intAddress,
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

func addMetadata(ctx context.Context) error {
	err := grpc.SetTrailer(ctx, metadata.Pairs("seaside-tail-bin", hex.EncodeToString(utils.GenerateReliableTail(GRPC_MAX_TAIL_LENGTH).Slice())))
	if err != nil {
		return fmt.Errorf("error adding metadata to the gRPC response: %v", err)
	} else {
		return nil
	}
}

// Authenticate viridian client.
// Check payload values, create user token and encrypt it with private key.
// Send the token to user.
// Should be applied for WhirlpoolServer object.
// Accept context and authentication request.
// Return authentication response and nil if authentication successful, otherwise nil and error.
func (server *WhirlpoolServer) AuthenticateClient(ctx context.Context, request *generated.WhirlpoolClientAuthenticationRequest) (*generated.WhirlpoolClientAuthenticationResponse, error) {
	// Create and marshall user token
	token := &generated.ClientToken{
		Name:         request.Name,
		Identifier:   request.Identifier,
		IsPrivileged: true,
		Subscription: request.Subscription,
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

	// Create and marshall user certificate
	certificate := &generated.SeasideWhirlpoolClientCertificate{
		Address:       server.address,
		TyphoonPublic: crypto.PRIVATE_KEY.PublicKey().Slice(),
		TyphoonPort:   uint32(server.typhoonPort),
		PortPort:      uint32(server.portPort),
		Token:         tokenData.Slice(),
		Dns:           SUGGESTED_DNS_SERVER,
	}

	// Create and marshall response
	err = addMetadata(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error adding metadata: %v", err)
	}
	return &generated.WhirlpoolClientAuthenticationResponse{
		Certificate: certificate,
	}, nil
}
