package main

import (
	"context"
	"flag"
	"main/tunnel"
	"main/utils"
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
	INTERNAL_ADDRESS = utils.GetEnv("SEASIDE_ADDRESS")
	EXTERNAL_ADDRESS = utils.GetEnv("SEASIDE_EXTERNAL")

	SEASIDE_PORT = utils.GetIntEnv("SEASIDE_SEAPORT")
	CONTROL_PORT = utils.GetIntEnv("SEASIDE_CTRLPORT")
	NETWORK_PORT = utils.GetIntEnv("SEASIDE_NETPORT")

	unparsedLevel := utils.GetEnv("SEASIDE_LOG_LEVEL")
	level, err := logrus.ParseLevel(unparsedLevel)
	if err != nil {
		logrus.Fatalf("Error parsing log level environmental variable: %v", unparsedLevel)
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

	// Initialize VPN connection
	err = InitializeSeasideConnection()
	if err != nil {
		logrus.Fatalf("Error initializing seaside connection: %v", err)
	}

	// Initialize context for goroutines stopping
	ctx, cancel := context.WithCancel(context.Background())

	// Start goroutines for packet forwarding
	go ListenControlPort(ctx, INTERNAL_ADDRESS, CONTROL_PORT)
	go ReceivePacketsFromViridian(ctx, tunnelConfig.Tunnel, tunnelConfig.Network)
	go SendPacketsToViridian(ctx, tunnelConfig.Tunnel, tunnelConfig.Network)

	// Start web API, connect to surface if available
	go InitNetAPI(ctx, NETWORK_PORT)
	go ExchangeNodeKey()

	// Prepare termination signal
	exitSignal := make(chan os.Signal, 1)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal

	// Send termination signal to goroutines and close VPN connection
	cancel()
	SEA_CONNECTION.Close()

	// Disable tunnel and restore firewall config
	tunnelConfig.Close()
}
