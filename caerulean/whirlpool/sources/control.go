package main

import (
	"crypto/cipher"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

const CTRLBUFFERSIZE = 5000

type Viridian struct {
	aead   cipher.AEAD
	expire *time.Timer
}

var (
	VIRIDIANS       map[string]Viridian
	CTRL_CONNECTION *net.UDPConn
	USER_TTL        = time.Minute * time.Duration(*user_ttl)
)

func ListenControlPort(ip string, port int) {
	network := fmt.Sprintf("%s:%d", ip, port)

	gateway, err := net.ResolveUDPAddr(UDP, network)
	if err != nil {
		logrus.Fatalf("Couldn't resolve address (%s): %v", network, err)
	}

	CTRL_CONNECTION, err := net.ListenUDP(UDP, gateway)
	if err != nil {
		logrus.Fatalf("Couldn't resolve connection (%s): %v", gateway.String(), err)
	}

	defer CTRL_CONNECTION.Close()
	buffer := make([]byte, CTRLBUFFERSIZE)

	for {
		r, addr, err := CTRL_CONNECTION.ReadFromUDP(buffer)
		if err != nil || r == 0 {
			logrus.Errorf("Reading control error (%d bytes read): %v", r, err)
			return
		}

		address := addr.String()
		logrus.Infoln("Received control message from user:", address)

		data := buffer[r:]
		viridian, exists := VIRIDIANS[address]
		if exists {
			data, err = DecryptSymmetrical(viridian.aead, buffer[r:])
			if err != nil {
				logrus.Warnln("Couldn't decrypt message from user", address)
				SendProtocolToUser(ERROR, addr)
				return
			}
		}

		proto, data, err := ResolveMessage(exists, data)
		if err != nil {
			logrus.Warnln("Couldn't parse message from user", address)
			SendProtocolToUser(ERROR, addr)
			return
		}

		var message, _ = EncodeMessage(UNDEF, nil)
		switch proto {
		case PUBLIC:
			message, err = prepareEncryptedSymmetricalKeyForUser(data, address)
			if err != nil {
				logrus.Warnf("Couldn't decrypt message from user %s: %v", address, err)
				message, _ = EncodeMessage(ERROR, nil)
			}
		case NO_PASS:
			delete(VIRIDIANS, address)
			message, _ = EncodeMessage(SUCCESS, nil)
		}

		logrus.Infoln("Sending result to user", address)
		CTRL_CONNECTION.WriteToUDP(message, addr)
	}
}

func SendProtocolToUser(proto Protocol, address *net.UDPAddr) {
	message, _ := EncodeMessage(proto, nil)
	CTRL_CONNECTION.WriteToUDP(message, address)
}

func prepareEncryptedSymmetricalKeyForUser(buffer []byte, address string) ([]byte, error) {
	aead, key, err := GenerateSymmetricalAlgorithm()
	if err != nil {
		logrus.Warnln("Couldn't create an encryption algorithm for user", address)
		return nil, err
	}

	deletion_timer := time.AfterFunc(USER_TTL, func() { delete(VIRIDIANS, address) })
	VIRIDIANS[address] = Viridian{aead, deletion_timer}

	public, err := ParsePublicKey(buffer)
	if err != nil {
		logrus.Warnln("Couldn't resolve public key of user", address)
		return nil, err
	}

	data, err := EncryptRSA(key, public)
	if err != nil {
		logrus.Warnln("Couldn't encrypt symmetrical key for user", address)
		return nil, err
	}

	logrus.Infoln("Symmetrical key prepared for user", address)
	return data, nil
}
