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
	MTU        = "1300"
)

var (
	localIP  = flag.String("local", "", "Local tun interface IP/MASK like 192.168.3.3/24")
	remoteIP = flag.String("remote", "", "Remote server (external) IP like 8.8.8.8")
	port     = flag.Int("port", 1723, "UDP port for communication")
)

func forwardFromUDPToTunnel(output *net.UDPConn, input *water.Interface) {
	buf := make([]byte, BUFFERSIZE)
	for {
		n, addr, err := output.ReadFromUDP(buf)
		header, _ := ipv4.ParseHeader(buf[:n])
		log.Printf("Received %d bytes from %v: %+v\n", n, addr, header)
		if err != nil || n == 0 {
			log.Println("Error: ", err)
			continue
		}
		input.Write(buf[:n])
	}
}

func forwardFromTunnelToUDP(output *water.Interface, input *net.UDPConn, remote *net.UDPAddr) {
	packet := make([]byte, BUFFERSIZE)
	for {
		plen, err := output.Read(packet)
		if err != nil {
			break
		}
		header, _ := ipv4.ParseHeader(packet[:plen])
		log.Printf("Sending to remote: %+v (%+v)\n", header, err)
		input.WriteToUDP(packet[:plen], remote)
	}
}

func main() {
	flag.Parse()
	if "" == *localIP {
		flag.Usage()
		log.Fatalln("\nLocal ip is not specified")
	}
	if "" == *remoteIP {
		flag.Usage()
		log.Fatalln("\nRemote server is not specified")
	}

	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatalln("Unable to allocate TUN interface:", err)
	}

	iname := iface.Name()
	AllocateInterface(iname, MTU, *localIP)
	ConfigureForwarding()

	remoteAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%v", *remoteIP, *port))
	if err != nil {
		log.Fatal(err)
	}

	s, err := net.ResolveUDPAddr("udp4", fmt.Sprintf(":%v", *port))
	if err != nil {
		log.Fatal(err)
	}

	connection, err := net.ListenUDP("udp4", s)
	if err != nil {
		log.Fatal(err)
	}

	defer connection.Close()
	go forwardFromUDPToTunnel(connection, iface)

	forwardFromTunnelToUDP(iface, connection, remoteAddr)
}
