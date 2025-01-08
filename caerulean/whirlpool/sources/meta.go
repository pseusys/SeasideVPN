package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"main/generated"
	"main/utils"
	"net"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	GENERATE_CERT_LENGTH = 4096
	GENERATE_CERT_SERIAL = 8 * 20
	GENERATE_CERT_YEARS  = 10
)

// Metaserver structure.
// Contains gRPC server and whirlpool server, also includes connection listener.
type MetaServer struct {
	// End handler of Whirlpool server API.
	whirlpoolServer *WhirlpoolServer

	// General purpose gRPC server.
	grpcServer *grpc.Server

	// gRPC connection listener.
	listener net.Listener
}

// Load TLS credentials from files.
// Certificates are expected to be in `certificates/cert.crt` and `certificates/cert.key` files.
// Certificates should be valid and contain `subjectAltName` for the current SEASIDE_ADDRESS.
func loadTLSCredentials() (credentials.TransportCredentials, error) {
	// Format server key and certificate paths
	certificatesPath := utils.GetEnv("SEASIDE_CERTIFICATE_PATH")
	keyPath := fmt.Sprintf("%s/cert.crt", certificatesPath)
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

// Start the metaserver.
// Accept context that will be used as base context.
// Return pointer to metaserver object.
func start(base context.Context) *MetaServer {
	// Create whirlpool server
	whirlpoolServer := createWhirlpoolServer(base)

	// Parse internal IP and control port from environment
	intIP := utils.GetEnv("SEASIDE_ADDRESS")
	ctrlPort := uint16(utils.GetIntEnv("SEASIDE_CTRLPORT", 16))

	// Create TCP listener for gRPC connections
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", intIP, ctrlPort))
	if err != nil {
		logrus.Fatalf("failed to listen: %v", err)
	}

	// Load TLS credentials from files
	credentials, err := loadTLSCredentials()
	if err != nil {
		logrus.Fatalf("failed to read credentials: %v", err)
	}

	// Create and start gRPC server
	grpcServer := grpc.NewServer(grpc.Creds(credentials))
	generated.RegisterWhirlpoolViridianServer(grpcServer, whirlpoolServer)

	// Launch server in goroutine and return the metaserver object
	go runServer(grpcServer, listener)
	return &MetaServer{
		whirlpoolServer: whirlpoolServer,
		grpcServer:      grpcServer,
		listener:        listener,
	}
}

// Run metaserver.
// Accept gRPC server and TCP connection listener.
func runServer(server *grpc.Server, listener net.Listener) {
	logrus.Infof("Starting gRPC server on address: %v", listener.Addr())
	if err := server.Serve(listener); err != nil {
		logrus.Fatalf("failed to serve: %v", err)
	}
}

// Stop metaserver.
// Should be applied for MetaServer object.
// Accept metaserver object pointer.
// Destroy gRPC and Whirlpool server, also close TCP listener.
func (server *MetaServer) stop() {
	server.grpcServer.GracefulStop()
	server.whirlpoolServer.destroyWhirlpoolServer()
	server.listener.Close()
}
