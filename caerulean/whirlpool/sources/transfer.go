package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

const BUFFER_OVERHEAD = 500

var IOBUFFERSIZE int

func init() {
	buff, err := strconv.Atoi(MTU)
	if err != nil {
		logrus.Fatalln("Couldn't parse MTU:", MTU)
	}
	IOBUFFERSIZE = buff + BUFFER_OVERHEAD
}

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
	buffer := make([]byte, IOBUFFERSIZE)

	// Open viridian incoming UDP connection
	connection := openConnection(fmt.Sprintf("%s:%d", *iIP, *input))
	defer connection.Close()

	for {
		// Read BUFFERSIZE of data
		r, addr, err := connection.ReadFromUDP(buffer)
		if err != nil || r == 0 {
			logrus.Errorf("Reading from viridian error (%d bytes read): %v", r, err)
			continue
		}

		packet, err := decryptPacket(buffer[:r], addr)
		if err != nil {
			logrus.Errorln("Decrypting packet error:", err)
			SendProtocolToUser(NO_PASS, addr)
			continue
		}

		// Parse IP header
		header, err := ipv4.ParseHeader(packet)
		if err != nil {
			logrus.Errorln("Parsing header error:", err)
			continue
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

func decryptPacket(packet []byte, address *net.UDPAddr) ([]byte, error) {
	viridian, exists := VIRIDIANS[address.String()]
	if !exists {
		return packet, nil
	}

	viridian.expire.Reset(USER_TTL)

	decrypted, err := DecryptSymmetrical(viridian.aead, packet)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func SendPacketsToViridian(tunnel *water.Interface) {
	buffer := make([]byte, IOBUFFERSIZE)

	// Open viridian outcoming UDP connection
	connection := openConnection(fmt.Sprintf("%s:%d", *iIP, *output))
	defer connection.Close()

	for {
		// Read BUFFERSIZE of data from tunnel
		r, err := tunnel.Read(buffer)
		if err != nil || r == 0 {
			logrus.Errorf("Reading from tunnel error (%d bytes read): %v", r, err)
			continue
		}

		// Parse IP header
		header, _ := ipv4.ParseHeader(buffer[:r])
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

		packet, err := decryptPacket(buffer[:r], gateway)
		if err != nil {
			logrus.Errorln("Encrypting packet error:", err)
			SendProtocolToUser(NO_PASS, gateway)
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
	viridian, exists := VIRIDIANS[address]
	if !exists {
		return packet, nil
	}

	encrypted, err := EncryptSymmetrical(viridian.aead, packet)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}
