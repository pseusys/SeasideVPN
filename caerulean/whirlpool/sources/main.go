package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/mdlayher/packet"
	"github.com/songgao/water"
)

const (
	BUFFERSIZE = 2000
	MTU        = "1300" // TODO: revise!
	TUNNEL_IP  = "192.168.0.87/24"
	PORT       = 1723
	IFACE      = "eth0"
	CIDR       = 24
)

var (
	ip   = flag.String("ip", "127.0.0.1", "External whirlpool IP")
	port = flag.Int("port", PORT, "UDP port for communication")
	cidr = flag.Int("cidr", CIDR, "External network CIDR")
)

func transferPackets(output *packet.Conn, input *water.Interface) {
	buf := make([]byte, BUFFERSIZE)
	out_iface, out_network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", *ip, *cidr))
	if err != nil {
		log.Fatal(err)
	}

	for {
		n, _, err := output.ReadFrom(buf)
		if err != nil {
			log.Println(err)
			continue
		}

		fromViridian, header, err := CheckFromViridian(buf, n, out_iface)
		if err != nil {
			log.Println(err)
			continue
		}

		if fromViridian {
			log.Printf("Received from viridian %d bytes: %+v\n", n, header)
			input.Write(buf[UDP_HEADER_LEN:n])
		} else if !IsSpecialNetworkAddress(header.Src, *out_network) {
			log.Printf("Sending to viridian %d bytes: %+v\n", n, header)
			input.Write(buf[:n])
		}
	}
}

func main() {
	flag.Parse()
	if "" == *ip {
		flag.Usage() // TODO: make more beautiful
		log.Fatalln("\nRemote server is not specified!")
	}

	tunnel, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatalln("Unable to allocate TUN interface:", err)
	}

	iface, err := net.InterfaceByName(IFACE)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := packet.Listen(iface, packet.Datagram, ETHERTYPE, nil)
	if err != nil {
		log.Fatal(err)
	}

	iname := tunnel.Name()
	AllocateInterface(iname, MTU, TUNNEL_IP)
	ConfigureForwarding(IFACE, iname)

	transferPackets(conn, tunnel)
}
