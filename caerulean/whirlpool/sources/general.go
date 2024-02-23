package main

import (
	"context"
	"fmt"
	"main/generated"
	"main/utils"
	"net"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type MetaServer struct {
	whirlpoolServer *WhirlpoolServer
	grpcServer      *grpc.Server
	listener        net.Listener
}

func start(base context.Context) *MetaServer {
	whirlpoolServer := createWhirlpoolServer(base)

	intIP := utils.GetEnv("SEASIDE_ADDRESS")
	ctrlPort := utils.GetIntEnv("SEASIDE_CTRLPORT")

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", intIP, ctrlPort))
	if err != nil {
		logrus.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
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
