package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/songgao/water"
)

const (
	TUNNEL_IP = "192.168.0.87/24"
	IFACE     = "eth0" // TODO: find the default interface name
	UDP       = "udp"
	PORT      = 1723
)

var (
	ip   = flag.String("i", "127.0.0.1", "External whirlpool IP")
	port = flag.Int("p", PORT, "UDP port for communication")
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

	gateway, err := net.ResolveUDPAddr(UDP, fmt.Sprintf("%s:%d", *ip, *port))
	if err != nil {
		log.Fatal(err)
	}

	connection, err := net.ListenUDP(UDP, gateway)
	if err != nil {
		log.Fatal(err)
	}

	go makePublic(connection, tunnel)
	go makePrivate(tunnel, connection)

	defer connection.Close()
	select {}
}
