package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

const (
	DEF_ADDRESS   = "none"
	TUNNEL_IP     = "192.168.0.87/24"
	UDP           = "udp4"
	TCP           = "tcp4"
	SEA_PORT      = 8542
	CONTROL_PORT  = 8543
	USER_TTL      = 300
	MAX_USERS     = 16
	DEF_LOG_LEVEL = "WARNING"
)

var (
	iIP       = flag.String("a", DEF_ADDRESS, "Internal whirlpool IP - towards viridian (required)")
	eIP       = flag.String("e", DEF_ADDRESS, "External whirlpool IP - towards outside world (default: same as internal address)")
	port      = flag.Int("p", SEA_PORT, fmt.Sprintf("UDP port for receiving UDP packets (default: %d)", SEA_PORT))
	control   = flag.Int("c", CONTROL_PORT, fmt.Sprintf("TCP port for communication with viridian (default: %d)", CONTROL_PORT))
	user_ttl  = flag.Int("t", USER_TTL, fmt.Sprintf("Time system keeps user password for without interaction, in minutes (default: %d hours)", USER_TTL/60))
	max_users = flag.Int("u", MAX_USERS, fmt.Sprintf("Maximum number of users, that are able to connect to this whirlpool node (default: %d)", MAX_USERS))
	help      = flag.Bool("h", false, "Print this message again and exit")
)

func init() {
	level, err := logrus.ParseLevel(getEnv("LOG_LEVEL", DEF_LOG_LEVEL))
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

	if *iIP == DEF_ADDRESS {
		logrus.Fatalln("Internal whirlpool IP (towards viridian) is not specified (but required)!")
	}

	if *eIP == DEF_ADDRESS {
		*eIP = *iIP
	}

	// Create and get IP for tunnel interface
	tunnelAddress, tunnelNetwork, err := net.ParseCIDR(TUNNEL_IP)
	if err != nil {
		logrus.Fatalf("Couldn't parse tunnel network address (%s): %v", TUNNEL_IP, err)
	}

	tunnel, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		logrus.Fatalln("Unable to allocate TUN interface:", err)
	}

	// Find interface names for give IP addresses
	internalInterface, err := FindAddress(*iIP)
	if err != nil {
		logrus.Fatalf("Couldn't find any interface for IP %s: %v", *iIP, err)
	}

	externalInterface, err := FindAddress(*eIP)
	if err != nil {
		logrus.Fatalf("Couldn't find any interface for IP %s: %v", *eIP, err)
	}

	// Create and configure tunnel interface
	iname := tunnel.Name()
	AllocateInterface(iname, &tunnelAddress, tunnelNetwork)
	ConfigureForwarding(internalInterface, externalInterface, iname, &tunnelAddress)

	// Start goroutines for packet forwarding
	go ListenControlPort(*iIP, *control)
	go ReceivePacketsFromViridian(tunnel)
	go SendPacketsToViridian(tunnel)

	exitSignal := make(chan os.Signal)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal

	// TODO: notify clients (if needed)
}
