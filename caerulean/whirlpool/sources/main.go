package main

import (
	"flag"
	"log"
	"net"

	"github.com/songgao/water"
)

const (
	TUNNEL_IP    = "192.168.0.87/24"
	IFACE        = "eth0" // TODO: find the default interface name
	UDP          = "udp4"
	INPUT_PORT   = 1723
	OUTPUT_PORT  = 1724
	CONTROL_PORT = 1725
)

var (
	ip      = flag.String("a", "127.0.0.1", "External whirlpool IP")
	input   = flag.Int("i", INPUT_PORT, "UDP port for receiving UDP packets")
	output  = flag.Int("o", OUTPUT_PORT, "UDP port for sending UDP packets")
	control = flag.Int("c", CONTROL_PORT, "UDP port for communication with Surface")
)

func main() {
	flag.Parse()
	if "" == *ip {
		flag.Usage() // TODO: revise
		log.Fatalln("\nRemote server is not specified!")
	}

	tunnel_address, tunnel_network, err := net.ParseCIDR(TUNNEL_IP)
	if err != nil {
		log.Fatal(err)
	}

	tunnel, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatalln("Unable to allocate TUN interface:", err)
	}

	iname := tunnel.Name()
	AllocateInterface(iname, &tunnel_address, tunnel_network)
	ConfigureForwarding(IFACE, iname, &tunnel_address)

	go ReceivePacketsFromViridian(tunnel)
	go SendPacketsToViridian(tunnel)
	select {}
}
