package main

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"main/m/v2/generated"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

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

func connectViridian(userID string, encrypted_token []byte) generated.UserControlResponseStatus {
	token := &generated.UserToken{}
	err := UnmarshalDecrypting(encrypted_token, SYMM_NODE_AEAD, token, false)
	if err != nil {
		logrus.Warnln("Couldn't parse token from user", userID, err)
		return generated.UserControlResponseStatus_ERROR
	}

	if !token.Privileged && token.Subscription.AsTime().Before(time.Now().UTC()) {
		logrus.Warnln("User subscription outdated, cannot connect VPN user", userID)
		return generated.UserControlResponseStatus_OVERTIME
	} else if !token.Privileged && len(VIRIDIANS) >= *max_users {
		logrus.Warnln("User number overload, cannot connect VPN user", userID)
		return generated.UserControlResponseStatus_OVERLOAD
	} else {
		// Parse user XChaCha-Poly1305 key
		aead, err := ParseSymmetricalAlgorithm(token.Session)
		if err != nil {
			logrus.Warnln("Couldn't parse encryption algorithm for user", userID)
			return generated.UserControlResponseStatus_ERROR
		}
		// Setup inactivity deletion timer for user
		deletionTimer := time.AfterFunc(USER_LIFETIME, func() { deleteViridian(userID, true) })
		VIRIDIANS[userID] = Viridian{aead, deletionTimer}
		logrus.Infoln("Connected user", userID)
		return generated.UserControlResponseStatus_SUCCESS
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

	for {
		// Accept the incoming TCP connection
		connection, err := listener.AcceptTCP()
		if err != nil {
			logrus.Fatalf("Couldn't resolve connection (%s): %v", gateway.String(), err)
		}

		// Read CTRLBUFFERSIZE of data from viridian
		buffer, err := io.ReadAll(connection)
		if err != nil {
			logrus.Errorf("Reading control error: %v", err)
			continue
		}

		// Resolve viridian TCP address
		address, err := net.ResolveTCPAddr(TCP, connection.RemoteAddr().String())
		if err != nil {
			logrus.Errorf("Resolving remote user address error: %v", connection.RemoteAddr().String())
			continue
		}

		userID := address.IP.String()
		logrus.Infoln("Received control message from user:", userID)

		// Resolve received message
		control := &generated.UserControlMessage{}
		err = UnmarshalDecrypting(buffer, RSA_NODE_KEY, control, true)
		if err != nil {
			logrus.Warnln("Couldn't parse message from user", userID, err)
			SendMessageToUser(generated.UserControlResponseStatus_ERROR, address.IP, connection, true)
			return
		}

		// Prepare answer
		message := generated.UserControlResponseStatus_UNDEFINED
		switch control.Status {
		// In case of PUBLIC status - register user
		case generated.UserControlRequestStatus_CONNECTION:
			logrus.Infoln("Connecting user", userID)
			message = connectViridian(userID, control.Token)
		// In case of TERMIN status - delete user record
		case generated.UserControlRequestStatus_DISCONNECTION:
			logrus.Infoln("Deleting user", userID)
			deleteViridian(userID, false)
			message = generated.UserControlResponseStatus_SUCCESS
		// Default action - send user undefined status
		default:
			logrus.Infof("Unexpected status %v received from user %s", control.Status, userID)
			message = generated.UserControlResponseStatus_UNDEFINED
		}

		// Send answer back to user
		logrus.Infoln("Sending result to user", userID)
		SendMessageToUser(message, address.IP, connection, true)
	}
}

func SendMessageToUser(message any, address net.IP, connection *net.TCPConn, closeConnection bool) {
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

	var payload []byte
	switch value := message.(type) {
	case []byte:
		payload = value
	case generated.UserControlResponseStatus:
		payload = []byte{byte(value)}
	default:
		payload = []byte{byte(generated.UserControlResponseStatus_ERROR)}
	}

	encoded, err := Obfuscate(payload, nil)
	if err != nil {
		logrus.Errorf("Sending message to user error: %v", err)
		return
	}

	var encrypted []byte
	viridian, exists := VIRIDIANS[address.String()]
	if !exists {
		encrypted = make([]byte, len(encoded))
		if _, err := rand.Read(encrypted); err != nil {
			logrus.Errorf("Sending message to user error: %v", err)
			return
		}
	} else {
		encrypted, err = EncryptSymmetrical(encoded, viridian.aead)
		if err != nil {
			logrus.Errorf("Sending message to user error: %v", err)
			return
		}
	}

	connection.Write(encrypted)

	if closeConnection {
		connection.Close()
	}
}
