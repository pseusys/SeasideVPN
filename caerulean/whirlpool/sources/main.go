package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

const (
	ADDRESS      = "127.0.0.1"
	TUNNEL_IP    = "192.168.0.87/24"
	UDP          = "udp4"
	INPUT_PORT   = 1723
	OUTPUT_PORT  = 1724
	CONTROL_PORT = 1725
)

var (
	iIP     = flag.String("a", ADDRESS, "Internal whirlpool IP - towards viridian (required)")
	eIP     = flag.String("e", ADDRESS, "External whirlpool IP - towards outside world (default: same as internal address)")
	input   = flag.Int("i", INPUT_PORT, fmt.Sprintf("UDP port for receiving UDP packets (default: %d)", INPUT_PORT))
	output  = flag.Int("o", OUTPUT_PORT, fmt.Sprintf("UDP port for sending UDP packets (default: %d)", OUTPUT_PORT))
	control = flag.Int("c", CONTROL_PORT, fmt.Sprintf("UDP port for communication with Surface (default: %d)", CONTROL_PORT))
	help    = flag.Bool("h", false, "Print this message again and exit")
)

func init() {
	level, err := logrus.ParseLevel(getEnv("LOG_LEVEL", "DEBUG"))
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

	if "" == *iIP {
		logrus.Fatalln("Internal whirlpool IP (towards viridian) is not specified (but required)!")
	}

	if "" == *eIP {
		eIP = iIP
	}

	// Create and get IP for tunnel interface
	tunnel_address, tunnel_network, err := net.ParseCIDR(TUNNEL_IP)
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
	AllocateInterface(iname, &tunnel_address, tunnel_network)
	ConfigureForwarding(internalInterface, externalInterface, iname, &tunnel_address)

	// Start goroutines for packet forwarding
	go ReceivePacketsFromViridian(tunnel)
	go SendPacketsToViridian(tunnel)
	select {}
}
