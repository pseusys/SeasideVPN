package main

import (
	"crypto/cipher"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
)

const (
	CTRLBUFFERSIZE = 5000
)

// TODO: setup key deletion timer
// TODO: random request and response length, hide data
var VIRIDIANS map[string]cipher.AEAD

func ListenControlPort(ip string, port int) {
	network := fmt.Sprintf("%s:%d", ip, port)

	gateway, err := net.ResolveTCPAddr(TCP, network)
	if err != nil {
		logrus.Fatalf("Couldn't resolve address (%s): %v", network, err)
	}

	listener, err := net.ListenTCP(TCP, gateway)
	if err != nil {
		logrus.Fatalf("Couldn't resolve connection (%s): %v", gateway.String(), err)
	}

	defer listener.Close()

	for {
		connection, err := listener.AcceptTCP()
		if err != nil {
			logrus.Errorf("Reading control error: %v", err)
			continue
		}

		handleViridianTCP(connection)
		connection.Close()
	}
}

func handleViridianTCP(connection *net.TCPConn) {
	buffer := make([]byte, CTRLBUFFERSIZE)

	r, err := connection.Read(buffer)
	if err != nil || r == 0 {
		logrus.Errorf("Reading control error (%d bytes read): %v", r, err)
	}

	address := connection.RemoteAddr().String()
	_, exists := VIRIDIANS[address]
	if !exists {
		sendEncryptedSymmetricalKeyToUser(buffer, connection, address)
	} else {
		delete(VIRIDIANS, address)
	}
}

func sendEncryptedSymmetricalKeyToUser(buffer []byte, connection *net.TCPConn, address string) {
	aead, key, err := GenerateSymmetricalAlgorithm()
	if err != nil {
		logrus.Warnln("Couldn't create an encryption algorithm for user", address)
		return
	}
	VIRIDIANS[address] = aead

	public, err := ParsePublicKey(buffer)
	if err != nil {
		logrus.Warnln("Couldn't resolve public key of user", address)
		return
	}

	data, err := EncryptRSA(key, public)
	if err != nil {
		logrus.Warnln("Couldn't encrypt symmetrical key for user", address)
		return
	}

	logrus.Infoln("Sending RSA key to user", address)
	connection.Write(data)
}
