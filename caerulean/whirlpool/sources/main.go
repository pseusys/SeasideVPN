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

// Initialize package variables from environment variables and setup logging level.
func init() {
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
	err := tunnelConfig.Open()
	if err != nil {
		logrus.Fatalf("Error establishing network connections: %v", err)
	}

	// Initialize context for goroutines stopping
	ctx, cancel := context.WithCancel(context.Background())
	server := start(tunnel.NewContext(ctx, tunnelConfig))

	// Prepare termination signal
	exitSignal := make(chan os.Signal, 1)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal

	// Send termination signal to goroutines and close VPN connection
	cancel()
	server.stop()

	// Disable tunnel and restore firewall config
	tunnelConfig.Close()
}
