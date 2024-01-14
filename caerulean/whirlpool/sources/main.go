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
	NONE_ARG     = "none"
	UDP          = "udp4"
	TCP          = "tcp4"
	TUNNEL_IP    = "10.0.0.87/24"
	SEA_PORT     = 8542
	CONTROL_PORT = 8543
	NET_PORT     = 8587
)

var (
	iIP     = flag.String("a", NONE_ARG, "Internal whirlpool IP - towards viridian (required)")
	eIP     = flag.String("e", NONE_ARG, "External whirlpool IP - towards outside world (default: same as internal address)")
	port    = flag.Int("p", SEA_PORT, "UDP port for receiving UDP packets")
	control = flag.Int("c", CONTROL_PORT, "TCP port for communication with viridian")
	network = flag.Int("n", NET_PORT, "Network API port")
	help    = flag.Bool("h", false, "Print this message again and exit")
)

func init() {
	default_level := "INFO"
	level, err := logrus.ParseLevel(utils.GetEnv("LOG_LEVEL", &default_level))
	if err != nil {
		logrus.Fatalln("Couldn't parse log level environmental variable!")
	}
	logrus.SetLevel(level)
}

func main() {
	// Parse CLI args
	flag.Parse()
	if *help {
		flag.Usage()
		return
	}

	if *iIP == NONE_ARG {
		logrus.Fatalln("Internal whirlpool IP (towards viridian) is not specified (but required)!")
	}

	if *eIP == NONE_ARG {
		*eIP = *iIP
	}

	// Create and get IP for tunnel interface
	tunnelConfig := tunnel.Preserve()
	err := tunnelConfig.Open(TUNNEL_IP, *iIP, *eIP, *port, *network, *control)
	if err != nil {
		logrus.Fatalf("Error establishing network connections: %v", err)
	}

	// Resolve UDP address to send to
	gateway, err := net.ResolveUDPAddr(UDP, fmt.Sprintf("%s:%d", *iIP, *port))
	if err != nil {
		logrus.Fatalf("Couldn't resolve local address: %v", err)
	}

	// Open the corresponding UDP socket
	SEA_CONNECTION, err = net.ListenUDP(UDP, gateway)
	if err != nil {
		logrus.Fatalf("Couldn't resolve connection (%s): %v", gateway.String(), err)
	}

	// Start goroutines for packet forwarding
	go ListenControlPort(*iIP, *control)
	go ReceivePacketsFromViridian(tunnelConfig.Tunnel, tunnelConfig.Network)
	go SendPacketsToViridian(tunnelConfig.Tunnel, tunnelConfig.Network)

	// Start web API, connect to surface if available
	go InitNetAPI(*network)
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
