package main

import (
	"errors"
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
		// Read IOBUFFERSIZE of data
		r, address, err := connection.ReadFromUDP(buffer)
		if err != nil || r == 0 {
			logrus.Errorf("Reading from viridian error (%d bytes read): %v", r, err)
			continue
		}

		// Decrypt packet (if user is connected in VPN mode)
		packet, err := decryptPacket(buffer[:r], address)
		if err != nil {
			logrus.Errorln("Decrypting packet error:", err)
			SendStatusToUser(NO_PASS, address.IP, nil)
			continue
		}

		// Parse IP header
		header, err := ipv4.ParseHeader(packet)
		if err != nil {
			logrus.Errorln("Parsing header error:", err)
			continue
		}

		logrus.Infof("Received %d bytes from viridian %v (src: %v, dst: %v)", r, address, header.Src, header.Dst)

		// Write packet to tunnel
		s, err := tunnel.Write(packet)
		if err != nil || s == 0 {
			logrus.Errorf("Writing to tunnel error (%d bytes written): %v", s, err)
			continue
		}
	}
}

func decryptPacket(ciphertext []byte, address *net.UDPAddr) ([]byte, error) {
	viridian, exists := VIRIDIANS[address.IP.String()]
	if !exists {
		return nil, errors.New("user not registered")
	}
	if viridian.aead == nil {
		return ciphertext, nil
	}

	viridian.expire.Reset(USER_LIFETIME)

	plaintext, err := DecryptSymmetrical(viridian.aead, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func SendPacketsToViridian(tunnel *water.Interface) {
	buffer := make([]byte, IOBUFFERSIZE)

	// Open viridian outcoming UDP connection
	connection := openConnection(fmt.Sprintf("%s:%d", *iIP, *output))
	defer connection.Close()

	for {
		// Read IOBUFFERSIZE of data from tunnel
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

		// Encrypt packet (if user is connected in VPN mode)
		packet, err := encryptPacket(buffer[:r], gateway)
		if err != nil {
			logrus.Errorln("Encrypting packet error:", err)
			SendStatusToUser(NO_PASS, gateway.IP, nil)
			continue
		}

		logrus.Infof("Sending %d bytes to viridian %v (src: %v, dst: %v)", r, gateway, header.Src, header.Dst)

		// Send packet to viridian
		s, err := connection.WriteToUDP(packet, gateway)
		if err != nil || s == 0 {
			logrus.Errorf("Writing to viridian error (%d bytes written): %v", s, err)
			continue
		}
	}
}

func encryptPacket(plaintext []byte, address *net.UDPAddr) ([]byte, error) {
	viridian, exists := VIRIDIANS[address.IP.String()]
	if !exists {
		return nil, errors.New("user not registered")
	}
	if viridian.aead == nil {
		return plaintext, nil
	}

	ciphertext, err := EncryptSymmetrical(viridian.aead, plaintext)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}
