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
	// Open viridian control TCP connection
	network := fmt.Sprintf("%s:%d", ip, port)

	gateway, err := net.ResolveTCPAddr(TCP, network)
	if err != nil {
		logrus.Fatalf("Couldn't resolve address (%s): %v", network, err)
	}

	// Create a TCP listener
	listener, err := net.ListenTCP(TCP, gateway)
	if err != nil {
		logrus.Fatalf("Couldn't create listener (%s): %v", gateway.String(), err)
	}

	defer listener.Close()
	buffer := make([]byte, CTRLBUFFERSIZE)

	for {
		// Accept the incoming TCP connection
		connection, err := listener.AcceptTCP()
		if err != nil {
			logrus.Fatalf("Couldn't resolve connection (%s): %v", gateway.String(), err)
		}

		// Read CTRLBUFFERSIZE of data from viridian
		read, err := connection.Read(buffer)
		if err != nil || read == 0 {
			logrus.Errorf("Reading control error (%d bytes read): %v", read, err)
			continue
		}

		// Resolve viridian TCP address
		address, err := net.ResolveTCPAddr(TCP, connection.RemoteAddr().String())
		if err != nil || read == 0 {
			logrus.Errorf("Resolving remote user address error: %v", connection.RemoteAddr().String())
			continue
		}

		userID := address.IP.String()
		logrus.Infoln("Received control message from user:", userID)

		// Resolve received message
		status, data, err := DecodeMessage(buffer[:read])
		if err != nil {
			logrus.Warnln("Couldn't parse message from user", userID)
			SendStatusToUser(ERROR, nil, connection)
			continue
		}

		// Prepare answer
		var message, _ = EncodeMessage(UNDEF, nil)
		switch status {
		// In case of SUCCESS status - register user as PROXY user
		case SUCCESS:
			if len(VIRIDIANS) >= *max_users {
				logrus.Infoln("User number overload, cannot connect PROXY user", userID)
				message, _ = EncodeMessage(OVERLOAD, nil)
			} else {
				logrus.Infoln("PROXY connecting user", userID)
				deletionTimer := time.AfterFunc(USER_LIFETIME, func() { deleteViridian(userID, true) })
				VIRIDIANS[userID] = Viridian{nil, deletionTimer}
				message, _ = EncodeMessage(SUCCESS, nil)
			}
		// In case of PUBLIC status - register user as VPN user
		case PUBLIC:
			if len(VIRIDIANS) >= *max_users {
				logrus.Infoln("User number overload, cannot connect VPN user", userID)
				message, _ = EncodeMessage(OVERLOAD, nil)
			} else {
				logrus.Infoln("VPN connecting user", userID)
				message, err = prepareEncryptedSymmetricalKeyForUser(data, userID)
				if err != nil {
					logrus.Warnf("Couldn't decrypt message from user %s: %v", userID, err)
					message, _ = EncodeMessage(ERROR, nil)
				} else {
					message, _ = EncodeMessage(SUCCESS, message)
				}
			}
		// In case of NO_PASS status - delete user record
		case NO_PASS:
			logrus.Infoln("Deleting user", userID)
			deleteViridian(userID, false)
			message, _ = EncodeMessage(SUCCESS, nil)
		// Default action - send user undefined status
		default:
			logrus.Infof("Unexpected status %v received from user %s", status, userID)
			message, _ = EncodeMessage(UNDEF, nil)
		}

		// Send answer back to user
		logrus.Infoln("Sending result to user", userID)
		connection.Write(message)
		connection.Close()
	}
}

func SendStatusToUser(status Status, address net.IP, connection *net.TCPConn) {
	closeConnection := false
	if connection == nil {
		closeConnection = true

		remote, err := net.ResolveTCPAddr(TCP, fmt.Sprintf("%s:%d", address.String(), *control))
		if err != nil {
			logrus.Errorf("Resolving remote user address error: %v", address.String())
			return
		}

		connection, err = net.DialTCP(TCP, nil, remote)
		if err != nil {
			logrus.Errorf("Dialing via TCP error to address: %v", address.String())
			return
		}
	}

	message, _ := EncodeMessage(status, nil)
	connection.Write(message)

	if closeConnection {
		connection.Close()
	}
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
