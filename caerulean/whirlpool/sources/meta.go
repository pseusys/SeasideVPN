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

type MetaServer struct {
	whirlpoolServer *WhirlpoolServer
	grpcServer      *grpc.Server
	listener        net.Listener
}

func loadTLSCredentials() (credentials.TransportCredentials, error) {
	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair("certificates/cert.crt", "certificates/cert.key")
	if err != nil {
		return nil, fmt.Errorf("error reading certificates: %v", err)
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
	}

	return credentials.NewTLS(config), nil
}

func start(base context.Context) *MetaServer {
	whirlpoolServer := createWhirlpoolServer(base)

	intIP := utils.GetEnv("SEASIDE_ADDRESS")
	ctrlPort := utils.GetIntEnv("SEASIDE_CTRLPORT")

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", intIP, ctrlPort))
	if err != nil {
		logrus.Fatalf("failed to listen: %v", err)
	}

	credentials, err := loadTLSCredentials()
	if err != nil {
		logrus.Fatalf("failed to read credentials: %v", err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(credentials))
	generated.RegisterWhirlpoolViridianServer(grpcServer, whirlpoolServer)

	go runServer(grpcServer, listener)
	return &MetaServer{
		whirlpoolServer: whirlpoolServer,
		grpcServer:      grpcServer,
		listener:        listener,
	}
}

func runServer(server *grpc.Server, listener net.Listener) {
	if err := server.Serve(listener); err != nil {
		logrus.Fatalf("failed to serve: %v", err)
	}
}

func (server *MetaServer) stop() {
	server.grpcServer.GracefulStop()
	server.whirlpoolServer.destroyWhirlpoolServer()
	server.listener.Close()
}
