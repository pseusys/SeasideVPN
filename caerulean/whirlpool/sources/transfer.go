package main

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

const IOBUFFERSIZE = 2000

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
	buf := make([]byte, IOBUFFERSIZE)

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

		address := addr.String()
		packet, err := decryptPacket(buf[:r], address)
		if err != nil {
			logrus.Errorln("Decrypting packet error:", err)
			continue
		}

		// Parse IP header
		header, err := ipv4.ParseHeader(packet)
		if err != nil {
			logrus.Errorln("Parsing header error:", err)
			continue
		}

		// Read the rest of the packet if it exceeds BUFFERSIZE
		// Can only happen if MTU is greater than BUFFERSIZE
		if r == IOBUFFERSIZE && header.TotalLen > IOBUFFERSIZE {
			r, packet, err = extendPacket(packet, header, connection, address)
			if err != nil {
				logrus.Errorf("Reading extra length from viridian error (%d bytes read): %v", r, err)
				continue
			}
		}

		logrus.Infof("Received %d bytes from viridian %v (src: %v, dst: %v)", r, addr, header.Src, header.Dst)

		// Write packet to tunnel
		s, err := tunnel.Write(packet)
		if err != nil || s == 0 {
			logrus.Errorln("Writing to tunnel error (%d bytes written): %v", s, err)
			continue
		}
	}
}

func extendPacket(packet []byte, header *ipv4.Header, connection *net.UDPConn, address string) (int, []byte, error) {
	packetLen := header.TotalLen - IOBUFFERSIZE
	extension := make([]byte, packetLen)

	r, _, err := connection.ReadFromUDP(extension)
	if err != nil || r != packetLen {
		return -1, nil, err
	}

	extension, err = decryptPacket(extension[:r], address)
	if err != nil {
		return -1, nil, err
	}

	return r + IOBUFFERSIZE, append(packet, extension...), nil
}

func decryptPacket(packet []byte, address string) ([]byte, error) {
	aead, exists := VIRIDIANS[address]
	if !exists {
		return packet, nil
	}

	decrypted, err := DecryptSymmetrical(aead, packet)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func SendPacketsToViridian(tunnel *water.Interface) {
	buf := make([]byte, IOBUFFERSIZE)

	// Open viridian outcoming UDP connection
	connection := openConnection(fmt.Sprintf("%s:%d", *iIP, *output))
	defer connection.Close()

	for {
		// Read BUFFERSIZE of data from tunnel
		r, err := tunnel.Read(buf)
		if err != nil || r == 0 {
			logrus.Errorf("Reading from tunnel error (%d bytes read): %v", r, err)
			continue
		}

		// Parse IP header
		header, _ := ipv4.ParseHeader(buf[:r])
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

		packet, err := decryptPacket(buf[:r], gateway.String())
		if err != nil {
			logrus.Errorln("Encrypting packet error:", err)
			continue
		}

		logrus.Infof("Sending %d bytes to viridian %v (src: %v, dst: %v)", r, gateway, header.Src, header.Dst)

		// Send packet to viridian
		s, err := connection.WriteToUDP(packet, gateway)
		if err != nil || s == 0 {
			logrus.Errorln("Writing to viridian error (%d bytes written): %v", s, err)
			continue
		}
	}
}

func encryptPacket(packet []byte, address string) ([]byte, error) {
	aead, exists := VIRIDIANS[address]
	if !exists {
		return packet, nil
	}

	encrypted, err := EncryptSymmetrical(aead, packet)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}
