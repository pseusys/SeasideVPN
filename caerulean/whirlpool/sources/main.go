package main

import (
	"flag"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

const (
	LOG_LEVEL    = "LOG_LEVEL"
	ADDRESS      = "127.0.0.1"
	TUNNEL_IP    = "192.168.0.87/24"
	IFACE        = "eth0" // TODO: find the default interface name (ip addr show)
	IFACE2       = "eth0"
	UDP          = "udp4"
	INPUT_PORT   = 1723
	OUTPUT_PORT  = 1724
	CONTROL_PORT = 1725
)

var (
	ip      = flag.String("a", ADDRESS, "External whirlpool IP")
	input   = flag.Int("i", INPUT_PORT, "UDP port for receiving UDP packets")
	output  = flag.Int("o", OUTPUT_PORT, "UDP port for sending UDP packets")
	control = flag.Int("c", CONTROL_PORT, "UDP port for communication with Surface")
)

func init() {
	level, err := logrus.ParseLevel(getEnv(LOG_LEVEL, "DEBUG"))
	if err != nil {
		logrus.Fatalln("Couldn't parse log level environmental variable!")
	}
	logrus.SetLevel(level)
}

func main() {
	flag.Parse()
	if "" == *ip {
		flag.Usage() // TODO: revise
		logrus.Fatalln("\nRemote server is not specified!")
	}

	tunnel_address, tunnel_network, err := net.ParseCIDR(TUNNEL_IP)
	if err != nil {
		logrus.Fatalf("Couldn't parse tunnel network address (%s): %v", TUNNEL_IP, err)
	}

	tunnel, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		logrus.Fatalln("Unable to allocate TUN interface:", err)
	}

	iname := tunnel.Name()
	AllocateInterface(iname, &tunnel_address, tunnel_network)
	ConfigureForwarding(IFACE, IFACE2, iname, &tunnel_address)

	go ReceivePacketsFromViridian(tunnel)
	go SendPacketsToViridian(tunnel)
	select {}
}
