package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"main/crypto"
	"main/generated"
	"main/users"
	"net"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func connectViridian(encryptedToken, address, gateway []byte, port uint32) (generated.ControlResponseStatus, *uint16) {
	if encryptedToken == nil {
		logrus.Warnf("Error: user (%v) token is null", address)
		return generated.ControlResponseStatus_ERROR, nil
	}

	plaintext, err := crypto.Decode(encryptedToken, false, crypto.PRIVATE_NODE_AEAD)
	if err != nil {
		logrus.Warnf("Error decrypting token from user (%v): %v", address, err)
		return generated.ControlResponseStatus_ERROR, nil
	}

	token := &generated.UserToken{}
	err = proto.Unmarshal(plaintext, token)
	if err != nil {
		logrus.Warnf("Error unmarshalling token from user %v: %v", address, err)
		return generated.ControlResponseStatus_ERROR, nil
	}

	if address == nil {
		logrus.Warnf("Error: user address is null (gateway: %v)", gateway)
		return generated.ControlResponseStatus_ERROR, nil
	} else {
		userID, status, err := users.AddViridian(token, address, gateway, port)
		if err != nil {
			logrus.Warnf("Error adding viridian: %v", err)
		}
		return status, userID
	}
}

func ListenControlPort(ctx context.Context, ip string, port int) {
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

	logrus.Debug("Control port listening started")
	defer listener.Close()

	for {
		select {
		case <-ctx.Done():
			logrus.Debug("Control port listening stopped")
			return
		default: // do nothing
		}

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
			sendMessageToSocket(generated.ControlResponseStatus_ERROR, fmt.Errorf("error reading control message (%d bytes read): %v", r, err), connection, nil)
			continue
		}

		// Resolve viridian TCP address
		address, err := net.ResolveTCPAddr(TCP, connection.RemoteAddr().String())
		if err != nil {
			sendMessageToSocket(generated.ControlResponseStatus_ERROR, fmt.Errorf("error resolving remote user address: %v", connection.RemoteAddr().String()), connection, nil)
			continue
		}

		// Decrypt received message
		requester := address.IP.String()
		plaintext, userID, err := crypto.Decrypt(buffer.Bytes(), crypto.PUBLIC_NODE_AEAD, true)
		if err != nil {
			sendMessageToSocket(generated.ControlResponseStatus_ERROR, fmt.Errorf("error decrypting message from IP %v: %v", requester, err), connection, nil)
			continue
		}

		// Unmarshall received message
		message := &generated.ControlRequest{}
		err = proto.Unmarshal(plaintext, message)
		if err != nil {
			sendMessageToSocket(generated.ControlResponseStatus_ERROR, fmt.Errorf("error unmarshalling request from IP %v: %v", requester, err), connection, nil)
			continue
		}

		if userID != nil {
			logrus.Infof("Received control message from user: %d", *userID)
		} else {
			logrus.Infof("Received control request from IP: %v", requester)
		}

		switch message.Status {
		// In case of PUBLIC status - register user
		case generated.ControlRequestStatus_CONNECTION:
			payload := message.GetConnection()
			status, userID := connectViridian(payload.Token, payload.Address, address.IP, uint32(payload.Port))
			logrus.Infof("Connecting new user: %d", *userID)
			sendMessageToSocket(status, nil, connection, userID)
		// In case of HEALTHPING status - update user deletion timer
		case generated.ControlRequestStatus_HEALTHPING:
			logrus.Infof("Healthcheck from user: %d", *userID)
			status, err := users.UpdateViridian(*userID, message.GetHealthcheck().NextIn)
			sendMessageToSocket(status, fmt.Errorf("error updating viridian: %v", err), connection, userID)
		// In case of TERMIN status - delete user record
		case generated.ControlRequestStatus_DISCONNECTION:
			logrus.Infof("Deleting user: %d", *userID)
			sendMessageToSocket(generated.ControlResponseStatus_SUCCESS, nil, connection, userID)
			users.DeleteViridian(*userID, false)
		// Default action - send user undefined status
		default:
			sendMessageToSocket(generated.ControlResponseStatus_UNDEFINED, fmt.Errorf("error status %v received from user %d", message.Status, *userID), connection, userID)
		}
	}
}
