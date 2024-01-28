package main

import (
	"bytes"
	"context"
	"fmt"
	"main/crypto"
	"main/generated"
	"main/users"
	"net"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// Helper function, creates new viridians, parses and checks received token and address.
// Accepts encrypted user token, local network viridian address, address from that the message was received and viridian seaside port number.
// Returns ControlResponseStatus: (Success) if user is created, other status otherwise.
// Also returns viridian ID pointer: nil if user is not created, uint16 pointer otherwise.
func connectViridian(encryptedToken, address, gateway []byte, port uint32) (generated.ControlResponseStatus, *uint16) {
	// Check if token is not null
	if encryptedToken == nil {
		logrus.Warnf("Error: user (%v) token is null", address)
		return generated.ControlResponseStatus_ERROR, nil
	}

	// Decode token
	plaintext, err := crypto.Decode(encryptedToken, false, crypto.PRIVATE_NODE_AEAD)
	if err != nil {
		logrus.Warnf("Error decrypting token from user (%v): %v", address, err)
		return generated.ControlResponseStatus_ERROR, nil
	}

	// Unmarshall token datastructure
	token := &generated.UserToken{}
	err = proto.Unmarshal(plaintext, token)
	if err != nil {
		logrus.Warnf("Error unmarshalling token from user %v: %v", address, err)
		return generated.ControlResponseStatus_ERROR, nil
	}

	// Check if address is not null, if so add viridian
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

// Helper function, updates viridian, resets healthcheck deletion timer.
// Accepts target viridian ID and next healthping request timeout.
// Returns ControlResponseStatus: (Healthpong) if user is updated, other status otherwise.
func updateViridian(userID *uint16, nextIn int32) generated.ControlResponseStatus {
	status, err := users.UpdateViridian(*userID, nextIn)
	if err != nil {
		logrus.Warnf("Error updating viridian: %v", err)
	}
	return status
}

// Set up CONTROL port listener, it accepts and processes viridian control messages.
// Accepts Context for graceful termination, internal IP (as a string) and CTRL port (as an int).
// NB! this method is blocking, so it should be run as goroutine.
func ListenControlPort(ctx context.Context, ip string, port int) {
	var buffer bytes.Buffer

	// Open viridian control TCP connection
	network := fmt.Sprintf("%s:%d", ip, port)

	gateway, err := net.ResolveTCPAddr("tcp4", network)
	if err != nil {
		logrus.Fatalf("Error resolving address (%s): %v", network, err)
	}

	// Create a TCP listener
	listener, err := net.ListenTCP("tcp4", gateway)
	if err != nil {
		logrus.Fatalf("Error creating listener (%s): %v", gateway.String(), err)
	}

	logrus.Debug("Control port listening started")
	defer listener.Close()

	// Listen to TCP CTRL requests
	for {
		select {
		case <-ctx.Done():
			logrus.Debug("Control port listening stopped")
			return
		default: // Do nothing
		}

		// Clear the buffer
		buffer.Reset()

		// Accept the incoming TCP connection
		connection, err := listener.AcceptTCP()
		if err != nil {
			logrus.Fatalf("Error resolving connection (%s): %v", gateway.String(), err)
		}

		// Resolve viridian TCP address
		address, err := net.ResolveTCPAddr("tcp4", connection.RemoteAddr().String())
		if err != nil {
			sendMessageToSocket(generated.ControlResponseStatus_ERROR, fmt.Errorf("error resolving remote user address: %v", connection.RemoteAddr().String()), connection, nil)
			continue
		}

		// Resolve viridian IP address string and decrypt request
		requester := address.IP.String()
		message := &generated.ControlRequest{}
		userID, err := readMessageFromSocket(connection, buffer, requester, message)
		if err != nil {
			sendMessageToSocket(generated.ControlResponseStatus_ERROR, fmt.Errorf("error decrypting request from IP %v: %v", requester, err), connection, nil)
			continue
		}

		// Print control message information
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
			nextIn := message.GetHealthcheck().NextIn
			logrus.Infof("Healthcheck from user: %d, next in %d", *userID, nextIn)
			status := updateViridian(userID, nextIn)
			sendMessageToSocket(status, nil, connection, userID)
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
