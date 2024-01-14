package main

import (
	"fmt"
	"io"
	"main/crypto"
	"main/generated"
	"main/users"
	"net"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func connectViridian(encryptedToken []byte, address []byte, gateway []byte) (generated.UserControlResponseStatus, *uint16) {
	if encryptedToken == nil {
		logrus.Warnf("User address is null")
		return generated.UserControlResponseStatus_ERROR, nil
	}

	plaintext, err := crypto.Decode(encryptedToken, false, crypto.PRIVATE_NODE_AEAD)
	if err != nil {
		logrus.Warnln("Couldn't decrypt token from user", err)
		return generated.UserControlResponseStatus_ERROR, nil
	}

	token := &generated.UserToken{}
	err = proto.Unmarshal(plaintext, token)
	if err != nil {
		logrus.Warnln("Couldn't unmarshall token from user", err)
		return generated.UserControlResponseStatus_ERROR, nil
	}

	if address == nil {
		logrus.Warnf("User address is null")
		return generated.UserControlResponseStatus_ERROR, nil
	} else {
		userID, status, err := users.AddViridian(token, address, gateway)
		if err != nil {
			logrus.Warnln("Couldn't add viridian", err)
		}
		return status, userID
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

		// Decrypt received message
		requester := address.IP.String()
		plaintext, userID, err := crypto.Decrypt(buffer, crypto.PUBLIC_NODE_AEAD, true)
		if err != nil {
			logrus.Warnln("Couldn't decrypt message from IP", requester, err)
			users.SendMessageToUser(generated.UserControlResponseStatus_ERROR, connection, nil)
			continue
		}

		// Unmarshall received message
		message := &generated.UserControlMessage{}
		err = proto.Unmarshal(plaintext, message)
		if err != nil {
			logrus.Warnln("Couldn't unmarshall request from IP", requester, err)
			users.SendMessageToUser(generated.UserControlResponseStatus_ERROR, connection, nil)
			continue
		}

		if userID != nil {
			logrus.Infoln("Received control message from user", *userID)
		} else {
			logrus.Infoln("Received control request from IP", requester)
		}

		switch message.Status {
		// In case of PUBLIC status - register user
		case generated.UserControlRequestStatus_CONNECTION:
			payload := message.GetConnection()
			status, userID := connectViridian(payload.Token, payload.Address, address.IP)
			logrus.Infoln("Connecting new user", *userID)
			users.SendMessageToUser(status, connection, userID)
		// In case of HEALTHPING status - update user deletion timer
		case generated.UserControlRequestStatus_HEALTHPING:
			logrus.Infoln("Healthcheck from user", *userID)
			status, err := users.UpdateViridian(*userID, message.GetHealthcheck().NextIn)
			if err != nil {
				logrus.Warnln("Healthping error", err)
			}
			users.SendMessageToUser(status, connection, userID)
		// In case of TERMIN status - delete user record
		case generated.UserControlRequestStatus_DISCONNECTION:
			logrus.Infoln("Deleting user", *userID)
			users.SendMessageToUser(generated.UserControlResponseStatus_SUCCESS, connection, userID)
			users.DeleteViridian(*userID, false)
		// Default action - send user undefined status
		default:
			logrus.Infof("Unexpected status %v received from user %d", message.Status, *userID)
			users.SendMessageToUser(generated.UserControlResponseStatus_UNDEFINED, connection, userID)
		}
	}
}
