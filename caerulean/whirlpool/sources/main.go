package main

import (
	"flag"
	"main/m/v2/generated"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

const (
	NONE_ARG      = "none"
	TUNNEL_IP     = "192.168.0.87/24"
	UDP           = "udp4"
	TCP           = "tcp4"
	SEA_PORT      = 8542
	CONTROL_PORT  = 8543
	NET_PORT      = 8587
	USER_TTL      = 300
	MAX_USERS     = 16
	DEF_LOG_LEVEL = "WARNING"
)

var (
	iIP       = flag.String("a", NONE_ARG, "Internal whirlpool IP - towards viridian (required)")
	eIP       = flag.String("e", NONE_ARG, "External whirlpool IP - towards outside world (default: same as internal address)")
	surfaceIP = flag.String("s", NONE_ARG, "Network surface address (required for network usage)")
	port      = flag.Int("p", SEA_PORT, "UDP port for receiving UDP packets")
	control   = flag.Int("c", CONTROL_PORT, "TCP port for communication with viridian")
	network   = flag.Int("n", NET_PORT, "Network API port")
	user_ttl  = flag.Int("t", USER_TTL, "Time system keeps user password for without interaction, in minutes")
	max_users = flag.Int("u", MAX_USERS, "Maximum number of users, that are able to connect to this whirlpool node")
	help      = flag.Bool("h", false, "Print this message again and exit")
)

func init() {
	flag.StringVar(&NODE_OWNER_KEY, "o", NONE_ARG, "Node owner key string (required)")
}

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

	if *iIP == NONE_ARG {
		logrus.Fatalln("Internal whirlpool IP (towards viridian) is not specified (but required)!")
	}

	if *eIP == NONE_ARG {
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
	ConfigureForwarding(externalInterface, internalInterface, iname, &tunnelAddress)

	// Start goroutines for packet forwarding
	go ListenControlPort(*iIP, *control)
	go ReceivePacketsFromViridian(tunnel)
	go SendPacketsToViridian(tunnel)

	// Start web API, connect to surface if available
	go InitNetAPI(*network)
	err = RetrieveNodeKey()
	if err != nil {
		logrus.Fatalf("Initial symmetric node ciphering failed: %v", err)
	}

	// Prepare termination signal
	exitSignal := make(chan os.Signal, 1)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	<-exitSignal

	// Send disconnection status to all connected users
	for k := range VIRIDIANS {
		SendMessageToUser(generated.UserControlResponseStatus_TERMINATED, net.ParseIP(k), nil, true)
	}
}
