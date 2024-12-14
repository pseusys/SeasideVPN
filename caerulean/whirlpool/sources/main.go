// Whirlpool represents a simple Seaside VPN "worker" node.
// It accepts packages from Seaside viridians and transfers them to the internet.
// It is only supposed to be run on Linux as it uses unix-only TUN devices.
// The node can be run either freestanding (for users with admin permissions) or as a part of seaside network.
// It is not supposed to perform any "demanding" operations, such as database connections, etc.
// For any additional functionality, seaside network should be used.
package main

import (
	"context"
	"fmt"
	"io"
	"log/syslog"
	"main/tunnel"
	"main/utils"
	"os"
	"os/signal"
	"syscall"

	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
	"github.com/sirupsen/logrus/hooks/writer"
)

const (
	// Current Whirlpool distribution version.
	VERSION = "0.0.2"

	// Path for storing logs, two files will be created there: "danger.log" and "safe.log".
	LOG_PATH = "logs"
)

// Initialize package variables from environment variables and setup logging level.
func init() {
	unparsedLevel := utils.GetEnv("SEASIDE_LOG_LEVEL")
	level, err := logrus.ParseLevel(unparsedLevel)
	if err != nil {
		logrus.Fatalf("Error parsing log level environmental variable: %v", unparsedLevel)
	}
	logrus.SetLevel(level)

	hook, err := logrus_syslog.NewSyslogHook("udp", "localhost:514", syslog.LOG_INFO, "seaside-whirlpool")
	if err != nil {
		logrus.Error("Unable to connect to local syslog daemon!")
	} else {
		logrus.AddHook(hook)
	}

	logrus.SetOutput(io.Discard)
	logrus.AddHook(&writer.Hook{
		Writer: os.Stderr,
		LogLevels: []logrus.Level{
			logrus.PanicLevel,
			logrus.FatalLevel,
			logrus.ErrorLevel,
			logrus.WarnLevel,
		},
	})
	safeLogPath := fmt.Sprintf("%s/safe.log", LOG_PATH)
	dangerLogPath := fmt.Sprintf("%s/danger.log", LOG_PATH)
	logrus.AddHook(lfshook.NewHook(
		lfshook.PathMap{
			logrus.PanicLevel: dangerLogPath,
			logrus.FatalLevel: dangerLogPath,
			logrus.ErrorLevel: dangerLogPath,
			logrus.WarnLevel:  dangerLogPath,
			logrus.InfoLevel:  safeLogPath,
			logrus.DebugLevel: safeLogPath,
		},
		&logrus.JSONFormatter{},
	))
}

func main() {
	logrus.Infof("Running Caerulean Whirlpool version %s...", VERSION)

	// Initialize tunnel interface and firewall rules
	tunnelConfig := tunnel.Preserve()
	err := tunnelConfig.Open()
	if err != nil {
		logrus.Fatalf("Error establishing network connections: %v", err)
	}

	// Initialize context and start metaserver
	ctx, cancel := context.WithCancel(context.Background())
	server := start(tunnel.NewContext(ctx, tunnelConfig))

	// Prepare termination signal
	exitSignal := make(chan os.Signal, 1)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal

	// Send termination signal to metaserver
	cancel()
	server.stop()

	// Disable tunnel and restore firewall configs
	tunnelConfig.Close()
}
