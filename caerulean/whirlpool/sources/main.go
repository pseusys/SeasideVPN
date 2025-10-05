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
	"main/protocol"
	"main/tunnel"
	"main/users"
	"main/utils"
	"os"
	"os/signal"
	"syscall"

	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
	"github.com/sirupsen/logrus/hooks/writer"
)

// Current Whirlpool distribution version.
const (
	DEFAULT_LOG_LEVEL = "INFO"
	DEFAULT_LOG_PATH  = "logs"
)

// Initialize package variables from environment variables and setup logging level.
func init() {
	unparsedLevel := utils.GetEnv("SEASIDE_LOG_LEVEL", DEFAULT_LOG_LEVEL)
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
	logrus.AddHook(&writer.Hook{
		Writer: os.Stdout,
		LogLevels: []logrus.Level{
			logrus.InfoLevel,
			logrus.DebugLevel,
		},
	})

	logPath := utils.GetEnv("SEASIDE_LOG_PATH", DEFAULT_LOG_PATH)
	safeLogPath := fmt.Sprintf("%s/safe.log", logPath)
	dangerLogPath := fmt.Sprintf("%s/danger.log", logPath)
	logrus.AddHook(lfshook.NewHook(
		lfshook.PathMap{
			logrus.PanicLevel: dangerLogPath,
			logrus.FatalLevel: dangerLogPath,
			logrus.ErrorLevel: dangerLogPath,
			logrus.WarnLevel:  dangerLogPath,
			logrus.InfoLevel:  safeLogPath,
			logrus.DebugLevel: safeLogPath,
		},
		new(logrus.JSONFormatter),
	))
}

func RunMain() error {
	logrus.Infof("Running Caerulean Whirlpool version %s...", protocol.VERSION)

	// Initialize tunnel interface and firewall rules
	tunnelConfig, err := tunnel.Preserve()
	if err != nil {
		return fmt.Errorf("error saving system properties: %v", err)
	}

	err = tunnelConfig.Open()
	if err != nil {
		return fmt.Errorf("error establishing network connections: %v", err)
	}
	defer tunnelConfig.Close()

	// Initialize viridian dictionary
	viridians, err := users.NewViridianDict()
	if err != nil {
		return fmt.Errorf("error creating viridian dictionary: %v", err)
	}
	defer viridians.Clear()

	// Initialize metaserver
	metaServer, err := NewMetaServer(viridians, tunnelConfig)
	if err != nil {
		return fmt.Errorf("error creating servers: %v", err)
	}
	defer metaServer.Stop()

	errorChan := make(chan error)
	defer close(errorChan)

	// Initialize context and start metaserver
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	ctx = tunnel.NewContext(ctx, tunnelConfig)
	ctx = users.NewContext(ctx, viridians)

	go metaServer.Start(ctx, errorChan)
	defer cancel()

	select {
	case <-ctx.Done():
		logrus.Info("Stopping whirlpool because of a signal interruption...")
		return nil
	case err := <-errorChan:
		logrus.Info("Stopping whirlpool because of an error...")
		return fmt.Errorf("error serving: %v", err)
	}
}

func main() {
	err := RunMain()
	if err != nil {
		logrus.Fatalf("Runtime error: %v", err)
	}
}
