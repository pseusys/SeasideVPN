package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

const (
	BUFFERSIZE = 2000
	MTU        = "1300" // TODO: revise!
	TUNNEL_IP  = "192.168.0.87/24"
	PORT       = 1723
	IFACE      = "eth0" // TODO: find the default interface name
	CIDR       = 24
	MARK       = 87
	UDP        = "udp4"
)

var (
	ip   = flag.String("ip", "127.0.0.1", "External whirlpool IP")
	port = flag.Int("port", PORT, "UDP port for communication")
)

func makePublic(output *net.UDPConn, input *water.Interface) {
	buf := make([]byte, BUFFERSIZE)
	for {
		n, addr, err := output.ReadFromUDP(buf)
		header, _ := ipv4.ParseHeader(buf[:n])
		log.Printf("Received %d bytes from viridian %v: %+v\n", n, addr, header)
		if err != nil || n == 0 {
			log.Println("Error: ", err)
			continue
		}
		input.Write(buf[:n])
	}
}

func makePrivate(output *water.Interface, input *net.UDPConn) {
	packet := make([]byte, BUFFERSIZE)
	for {
		plen, err := output.Read(packet)
		if err != nil {
			break
		}
		header, _ := ipv4.ParseHeader(packet[:plen]) // TODO: handle bigger packets
		gateway, err := net.ResolveUDPAddr(UDP, fmt.Sprintf("%s:%v", header.Dst.String(), PORT))
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Sending to viridian (%+v): %+v (%+v)\n", gateway, header, err)
		input.WriteToUDP(packet[:plen], gateway)
	}
}

func main() {
	flag.Parse()
	if "" == *ip {
		flag.Usage()
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

	gateway, err := net.ResolveUDPAddr(UDP, fmt.Sprintf("%s:%v", *ip, *port))
	if err != nil {
		log.Fatal(err)
	}

	connection, err := net.ListenUDP(UDP, gateway)
	if err != nil {
		log.Fatal(err)
	}

	defer connection.Close()
	go makePublic(connection, tunnel)

	go makePrivate(tunnel, connection)

	select {}
}
