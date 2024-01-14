package main

import (
	"flag"
	"fmt"
	"main/tunnel"
	"main/utils"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

const (
	UDP       = "udp4"
	TCP       = "tcp4"
	TUNNEL_IP = "172.16.0.1/12"
)

var (
	HELP_FLAG = flag.Bool("h", false, "Print this message again and exit")

	INTERNAL_ADDRESS string
	EXTERNAL_ADDRESS string
	SEASIDE_PORT     int
	CONTROL_PORT     int
	NETWORK_PORT     int
)

func init() {
	INTERNAL_ADDRESS = utils.GetEnv("SEASIDE_ADDRESS", nil)
	EXTERNAL_ADDRESS = utils.GetEnv("SEASIDE_EXTERNAL", nil)

	SEASIDE_PORT = utils.GetIntEnv("SEASIDE_SEAPORT", nil)
	CONTROL_PORT = utils.GetIntEnv("SEASIDE_CTRLPORT", nil)
	NETWORK_PORT = utils.GetIntEnv("SEASIDE_NETPORT", nil)

	default_level := "WARNING"
	level, err := logrus.ParseLevel(utils.GetEnv("SEASIDE_LOG_LEVEL", &default_level))
	if err != nil {
		logrus.Fatalln("Couldn't parse log level environmental variable!")
	}
	logrus.SetLevel(level)
}

func main() {
	// Parse CLI args
	flag.Parse()
	if *HELP_FLAG {
		flag.Usage()
		return
	}

	// Create and get IP for tunnel interface
	tunnelConfig := tunnel.Preserve()
	err := tunnelConfig.Open(TUNNEL_IP, INTERNAL_ADDRESS, EXTERNAL_ADDRESS, SEASIDE_PORT, NETWORK_PORT, CONTROL_PORT)
	if err != nil {
		logrus.Fatalf("Error establishing network connections: %v", err)
	}

	// Resolve UDP address to send to
	gateway, err := net.ResolveUDPAddr(UDP, fmt.Sprintf("%s:%d", INTERNAL_ADDRESS, SEASIDE_PORT))
	if err != nil {
		logrus.Fatalf("Couldn't resolve local address: %v", err)
	}

	// Open the corresponding UDP socket
	SEA_CONNECTION, err = net.ListenUDP(UDP, gateway)
	if err != nil {
		logrus.Fatalf("Couldn't resolve connection (%s): %v", gateway.String(), err)
	}

	// Start goroutines for packet forwarding
	go ListenControlPort(INTERNAL_ADDRESS, CONTROL_PORT)
	go ReceivePacketsFromViridian(tunnelConfig.Tunnel, tunnelConfig.Network)
	go SendPacketsToViridian(tunnelConfig.Tunnel, tunnelConfig.Network)

	// Start web API, connect to surface if available
	go InitNetAPI(NETWORK_PORT)
	go ExchangeNodeKey()

	// Prepare termination signal
	exitSignal := make(chan os.Signal, 1)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal

	// TODO: terminate goroutines
	// TODO: defer delete all users
	SEA_CONNECTION.Close()
	tunnelConfig.Close()
}
