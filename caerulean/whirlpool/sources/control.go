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
	VIRIDIANS     = make(map[string]Viridian, *max_users)
	USER_LIFETIME = time.Minute * time.Duration(*user_ttl)
)

func deleteViridian(userID string, timeout bool) {
	delete(VIRIDIANS, userID)
	if timeout {
		logrus.Infof("User %s deleted by inactivity timeout (%d minutes)", userID, *user_ttl)
	} else {
		logrus.Infof("User %s deleted successfully", userID)
	}
}

func ListenControlPort(ip string, port int) {
	// Open viridian control UDP connection
	network := fmt.Sprintf("%s:%d", ip, port)

	gateway, err := net.ResolveUDPAddr(UDP, network)
	if err != nil {
		logrus.Fatalf("Couldn't resolve address (%s): %v", network, err)
	}

	connection, err := net.ListenUDP(UDP, gateway)
	if err != nil {
		logrus.Fatalf("Couldn't resolve connection (%s): %v", gateway.String(), err)
	}

	defer connection.Close()
	buffer := make([]byte, CTRLBUFFERSIZE)

	for {
		// Read CTRLBUFFERSIZE of data from tunnel
		read, address, err := connection.ReadFromUDP(buffer)
		if err != nil || read == 0 {
			logrus.Errorf("Reading control error (%d bytes read): %v", read, err)
			return
		}

		userID := address.IP.String()
		logrus.Infoln("Received control message from user:", userID)

		// Decrypt message if a key exists for the specified userss
		received := buffer[:read]
		viridian, exists := VIRIDIANS[userID]
		if exists {
			received, err = DecryptSymmetrical(viridian.aead, received)
			if err != nil {
				logrus.Warnln("Couldn't decrypt message from user", userID)
				SendStatusToUser(ERROR, address, connection)
				return
			}
		}

		// Resolve received message
		status, data, err := ResolveMessage(received)
		if err != nil {
			logrus.Warnln("Couldn't parse message from user", userID)
			SendStatusToUser(ERROR, address, connection)
			return
		}

		// Prepare answer
		var message, _ = EncodeMessage(UNDEF, nil)
		switch status {
		case PUBLIC:
			if len(VIRIDIANS) >= *max_users {
				message, _ = EncodeMessage(OVERLOAD, nil)
			} else {
				message, err = prepareEncryptedSymmetricalKeyForUser(data, userID)
				if err != nil {
					logrus.Warnf("Couldn't decrypt message from user %s: %v", userID, err)
					message, _ = EncodeMessage(ERROR, nil)
				}
				message, _ = EncodeMessage(SUCCESS, message)
			}
		case NO_PASS:
			deleteViridian(userID, false)
			message, _ = EncodeMessage(SUCCESS, nil)
		}

		// Send answer back to user
		logrus.Infoln("Sending result to user", userID)
		connection.WriteToUDP(message, address)
	}
}

func SendStatusToUser(status Status, address *net.UDPAddr, connection *net.UDPConn) {
	message, _ := EncodeMessage(status, nil)
	connection.WriteToUDP(message, address)
}

func prepareEncryptedSymmetricalKeyForUser(buffer []byte, userID string) ([]byte, error) {
	// Generate XChaCha-Poly1305 key
	aead, key, err := GenerateSymmetricalAlgorithm()
	if err != nil {
		logrus.Warnln("Couldn't create an encryption algorithm for user", userID)
		return nil, err
	}

	// Setup inactivity deletion timer for user
	deletionTimer := time.AfterFunc(USER_LIFETIME, func() { deleteViridian(userID, true) })
	VIRIDIANS[userID] = Viridian{aead, deletionTimer}

	// Parse user public RSA key
	public, err := ParsePublicKey(buffer)
	if err != nil {
		logrus.Warnln("Couldn't resolve public key of user", userID)
		return nil, err
	}

	// Encrypt user XChaCha-Poly1305 key with public RSA key
	data, err := EncryptRSA(key, public)
	if err != nil {
		logrus.Warnln("Couldn't encrypt symmetrical key for user", userID)
		return nil, err
	}

	logrus.Infoln("Symmetrical key prepared for user", userID)
	return data, nil
}
