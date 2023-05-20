package main

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

const (
	BUFFERSIZE = 2000
)

func openConnection(address string) *net.UDPConn {
	// Resolve UDP address to send to
	gateway, err := net.ResolveUDPAddr(UDP, address)
	if err != nil {
		logrus.Fatalf("Couldn't resolve address (%s): %v", address, err)
	}

	// Open the corresponding UDP socket
	connection, err := net.ListenUDP(UDP, gateway)
	if err != nil {
		logrus.Fatalf("Couldn't resolve connection (%s): %v", gateway.String(), err)
	}

	return connection
}

func ReceivePacketsFromViridian(tunnel *water.Interface) {
	buf := make([]byte, BUFFERSIZE)

	// Open viridian incoming UDP connection
	connection := openConnection(fmt.Sprintf("%s:%d", *iIP, *input))
	defer connection.Close()

	for {
		// Read BUFFERSIZE of data
		r, addr, err := connection.ReadFromUDP(buf)
		if err != nil || r == 0 {
			logrus.Errorf("Reading from viridian error (%d bytes read): %v", r, err)
			continue
		}

		// Parse IP header
		header, err := ipv4.ParseHeader(buf[:r])
		if err != nil {
			logrus.Errorln("Parsing header error:", err)
			continue
		}

		// Read the rest of the packet if it exceeds BUFFERSIZE
		// Can only happen if MTU is greater than BUFFERSIZE
		if r == BUFFERSIZE && header.TotalLen > BUFFERSIZE {
			packetLen := header.TotalLen
			bufExt := make([]byte, packetLen)
			copy(bufExt, buf)
			r, _, err := connection.ReadFromUDP(bufExt[BUFFERSIZE:])
			if err != nil || r != packetLen-BUFFERSIZE {
				logrus.Errorf("Reading extra length from viridian error (%d bytes read): %v", r, err)
				continue
			}
			r = packetLen
			buf = bufExt
		}

		logrus.Infof("Received %d bytes from viridian %v (src: %v, dst: %v)", r, addr, header.Src, header.Dst)

		// Write packet to tunnel
		s, err := tunnel.Write(buf[:r])
		if err != nil || s == 0 {
			logrus.Errorln("Writing to tunnel error (%d bytes written): %v", s, err)
			continue
		}
	}
}

func SendPacketsToViridian(tunnel *water.Interface) {
	packet := make([]byte, BUFFERSIZE)

	// Open viridian outcoming UDP connection
	connection := openConnection(fmt.Sprintf("%s:%d", *iIP, *output))
	defer connection.Close()

	for {
		// Read BUFFERSIZE of data from tunnel
		r, err := tunnel.Read(packet)
		if err != nil || r == 0 {
			logrus.Errorf("Reading from tunnel error (%d bytes read): %v", r, err)
			continue
		}

		// Parse IP header
		header, _ := ipv4.ParseHeader(packet[:r])
		if err != nil {
			logrus.Errorln("Parsing header error:", err)
			continue
		}

		// Resolve viridian address to send to
		gateway, err := net.ResolveUDPAddr(UDP, fmt.Sprintf("%s:%v", header.Dst.String(), *output))
		if err != nil {
			logrus.Errorln("Parsing return address error:", err)
			continue
		}

		logrus.Infof("Sending %d bytes to viridian %v (src: %v, dst: %v)", r, gateway, header.Src, header.Dst)

		// Send packet to viridian
		s, err := connection.WriteToUDP(packet[:r], gateway)
		if err != nil || s == 0 {
			logrus.Errorln("Writing to viridian error (%d bytes written): %v", s, err)
			continue
		}
	}
}
