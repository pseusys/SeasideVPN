package main

import (
	"bytes"
	"fmt"
	"io"
	"main/crypto"
	"main/generated"
	"main/users"
	"net"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func connectViridian(encryptedToken, address, gateway []byte, port uint32) (generated.UserControlResponseStatus, *uint16) {
	if encryptedToken == nil {
		logrus.Warnf("Error: user (%v) token is null", address)
		return generated.UserControlResponseStatus_ERROR, nil
	}

	plaintext, err := crypto.Decode(encryptedToken, false, crypto.PRIVATE_NODE_AEAD)
	if err != nil {
		logrus.Warnf("Error decrypting token from user (%v): %v", address, err)
		return generated.UserControlResponseStatus_ERROR, nil
	}

	token := &generated.UserToken{}
	err = proto.Unmarshal(plaintext, token)
	if err != nil {
		logrus.Warnf("Error unmarshalling token from user %v: %v", address, err)
		return generated.UserControlResponseStatus_ERROR, nil
	}

	if address == nil {
		logrus.Warnf("Error: user address is null (gateway: %v)", gateway)
		return generated.UserControlResponseStatus_ERROR, nil
	} else {
		userID, status, err := users.AddViridian(token, address, gateway, port)
		if err != nil {
			logrus.Warnf("Error adding viridian: %v", err)
		}
		return status, userID
	}
}

func ListenControlPort(ip string, port int) {
	var buffer bytes.Buffer

	// Open viridian control TCP connection
	network := fmt.Sprintf("%s:%d", ip, port)

	gateway, err := net.ResolveTCPAddr(TCP, network)
	if err != nil {
		logrus.Fatalf("Error resolving address (%s): %v", network, err)
	}

	// Create a TCP listener
	listener, err := net.ListenTCP(TCP, gateway)
	if err != nil {
		logrus.Fatalf("Error creating listener (%s): %v", gateway.String(), err)
	}

	defer listener.Close()

	for {
		// Clear the buffer
		buffer.Reset()

		// Accept the incoming TCP connection
		connection, err := listener.AcceptTCP()
		if err != nil {
			logrus.Fatalf("Error resolving connection (%s): %v", gateway.String(), err)
		}

		// Read CTRLBUFFERSIZE of data from viridian
		r, err := io.Copy(&buffer, connection)
		if err != nil {
			sendMessageToSocket(generated.UserControlResponseStatus_ERROR, fmt.Errorf("error reading control message (%d bytes read): %v", r, err), connection, nil)
			continue
		}

		// Resolve viridian TCP address
		address, err := net.ResolveTCPAddr(TCP, connection.RemoteAddr().String())
		if err != nil {
			sendMessageToSocket(generated.UserControlResponseStatus_ERROR, fmt.Errorf("error resolving remote user address: %v", connection.RemoteAddr().String()), connection, nil)
			continue
		}

		// Decrypt received message
		requester := address.IP.String()
		plaintext, userID, err := crypto.Decrypt(buffer.Bytes(), crypto.PUBLIC_NODE_AEAD, true)
		if err != nil {
			sendMessageToSocket(generated.UserControlResponseStatus_ERROR, fmt.Errorf("error decrypting message from IP %v: %v", requester, err), connection, nil)
			continue
		}

		// Unmarshall received message
		message := &generated.UserControlMessage{}
		err = proto.Unmarshal(plaintext, message)
		if err != nil {
			sendMessageToSocket(generated.UserControlResponseStatus_ERROR, fmt.Errorf("error unmarshalling request from IP %v: %v", requester, err), connection, nil)
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
			status, userID := connectViridian(payload.Token, payload.Address, address.IP, uint32(payload.Port))
			logrus.Infoln("Connecting new user", *userID)
			sendMessageToSocket(status, nil, connection, userID)
		// In case of HEALTHPING status - update user deletion timer
		case generated.UserControlRequestStatus_HEALTHPING:
			logrus.Infoln("Healthcheck from user", *userID)
			status, err := users.UpdateViridian(*userID, message.GetHealthcheck().NextIn)
			sendMessageToSocket(status, err, connection, userID)
		// In case of TERMIN status - delete user record
		case generated.UserControlRequestStatus_DISCONNECTION:
			logrus.Infoln("Deleting user", *userID)
			sendMessageToSocket(generated.UserControlResponseStatus_SUCCESS, nil, connection, userID)
			users.DeleteViridian(*userID, false)
		// Default action - send user undefined status
		default:
			sendMessageToSocket(generated.UserControlResponseStatus_UNDEFINED, fmt.Errorf("error status %v received from user %d", message.Status, *userID), connection, userID)
		}
	}
}
