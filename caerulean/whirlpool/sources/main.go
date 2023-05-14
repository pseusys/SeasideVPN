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
)

var (
	ip   = flag.String("ip", "127.0.0.1", "External whirlpool IP")
	port = flag.Int("port", PORT, "UDP port for communication")
	cidr = flag.Int("cidr", CIDR, "External network CIDR")
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

func makePrivate(output *water.Interface, input *net.UDPConn, remote *net.UDPAddr) {
	packet := make([]byte, BUFFERSIZE)
	for {
		plen, err := output.Read(packet)
		if err != nil {
			break
		}
		header, _ := ipv4.ParseHeader(packet[:plen])
		log.Printf("Sending to viridian: %+v (%+v)\n", header, err)
		input.WriteToUDP(packet[:plen], remote)
	}
}

func main() {
	flag.Parse()
	if "" == *ip {
		flag.Usage()
		log.Fatalln("\nRemote server is not specified!")
	}

	tunnel, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatalln("Unable to allocate TUN interface:", err)
	}

	iname := tunnel.Name()
	AllocateInterface(iname, MTU, TUNNEL_IP)
	ConfigureForwarding(IFACE, iname)

	gateway, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%v", *ip, *port))
	if err != nil {
		log.Fatal(err)
	}

	connection, err := net.ListenUDP("udp4", gateway)
	if err != nil {
		log.Fatal(err)
	}

	defer connection.Close()
	go makePublic(connection, tunnel)

	go makePrivate(tunnel, connection, gateway)

	select {}
}
