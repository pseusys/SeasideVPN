// Whirlpool represents a simple Seaside VPN "worker" node.
// It accepts packages from Seaside viridians and transfers them to the internet.
// It is only supposed to be run on Linux as it uses unix-only TUN devices.
// The node can be run either freestanding (for users with admin permissions) or as a part of seaside network.
// It is not supposed to perform any "demanding" operations, such as database connections, etc.
// For any additional functionality, seaside network should be used.
package main

import (
	"context"
	"main/tunnel"
	"main/utils"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

// Tunnel IP address, also serves as gateway address for tunnel network interface.
// Last bits of the packet source network address are used to store state user information in "iptables" firewall.
// Last 2 bytes of will be used for attributing packages belonging to different viridians.
const TUNNEL_IP = "172.16.0.1/12"

var (
	// Internal node IP address - the address for viridians to connect.
	INTERNAL_ADDRESS string

	// Internal node IP address - the address the packets will be sent from.
	EXTERNAL_ADDRESS string

	// UDP port for viridian messages accepting.
	SEASIDE_PORT int

	// TCP port for control messages accepting.
	CONTROL_PORT int

	// TCP/HTTP port for network endpoints hosting.
	NETWORK_PORT int
)

// Initialize package variables from environment variables and setup logging level.
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
	// Create and get IP for tunnel interface
	tunnelConfig := tunnel.Preserve()
	err := tunnelConfig.Open(TUNNEL_IP, INTERNAL_ADDRESS, EXTERNAL_ADDRESS, SEASIDE_PORT, NETWORK_PORT, CONTROL_PORT)
	if err != nil {
		logrus.Fatalf("Error establishing network connections: %v", err)
	}

	// Initialize VPN connection
	err = InitializeSeasideConnection(INTERNAL_ADDRESS, SEASIDE_PORT)
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
	go InitNetAPI(ctx, INTERNAL_ADDRESS, NETWORK_PORT)
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
