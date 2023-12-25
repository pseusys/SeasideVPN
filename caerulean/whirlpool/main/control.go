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
	"google.golang.org/protobuf/proto"
)

type Viridian struct {
	aead    cipher.AEAD
	reset   *time.Timer
	address net.IP
	gateway net.IP
}

const (
	USER_WAITING_OVERTIME   = 5
	FIRST_HEALTHCHECK_DELAY = time.Minute * time.Duration(USER_WAITING_OVERTIME)
)

var (
	VIRIDIANS = make(map[uint16]Viridian, *max_users)
)

func deleteViridian(userID uint16, timeout bool) {
	delete(VIRIDIANS, userID)
	if timeout {
		logrus.Infof("User %d deleted by inactivity timeout", userID)
	} else {
		logrus.Infof("User %d deleted successfully", userID)
	}
}

func connectViridian(encryptedToken []byte, address []byte, gateway []byte) (generated.UserControlResponseStatus, *uint16) {
	if encryptedToken == nil {
		logrus.Warnf("User address is null")
		return generated.UserControlResponseStatus_ERROR, nil
	}

	token := &generated.UserToken{}
	_, err := UnmarshalDecrypting(encryptedToken, SYMM_NODE_AEAD, token, false)
	if err != nil {
		logrus.Warnln("Couldn't parse token from user", err)
		return generated.UserControlResponseStatus_ERROR, nil
	}

	if !token.Privileged && token.Subscription.AsTime().Before(time.Now().UTC()) {
		logrus.Warnln("User subscription outdated, cannot connect user")
		return generated.UserControlResponseStatus_OVERTIME, nil
	} else if !token.Privileged && len(VIRIDIANS) >= *max_users {
		logrus.Warnln("User number overload, cannot connect user")
		return generated.UserControlResponseStatus_OVERLOAD, nil
	} else if address == nil {
		logrus.Warnf("User address is null")
		return generated.UserControlResponseStatus_ERROR, nil
	} else {
		// Parse user XChaCha-Poly1305 key
		aead, err := ParseSymmetricalAlgorithm(token.Session)
		if err != nil {
			logrus.Warnln("Couldn't parse encryption algorithm for user")
			return generated.UserControlResponseStatus_ERROR, nil
		}
		// Setup inactivity deletion timer for user
		userID := uint16(RandomPermute(len(VIRIDIANS)))
		deletionTimer := time.AfterFunc(FIRST_HEALTHCHECK_DELAY, func() { deleteViridian(userID, true) })
		VIRIDIANS[userID] = Viridian{aead, deletionTimer, address, gateway}
		return generated.UserControlResponseStatus_SUCCESS, &userID
	}
}

func updateUser(userID uint16, nextIn int32) generated.UserControlResponseStatus {
	viridian, exists := VIRIDIANS[userID]
	if exists {
		viridian.reset.Reset(time.Duration(nextIn*USER_WAITING_OVERTIME) * time.Second)
		return generated.UserControlResponseStatus_HEALTHPONG
	} else {
		return generated.UserControlResponseStatus_ERROR
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

		// Resolve received message
		requester := address.IP.String()
		control := &generated.UserControlMessage{}
		userID, err := UnmarshalDecrypting(buffer, RSA_NODE_KEY, control, true)
		if err != nil {
			logrus.Warnln("Couldn't parse message from IP", requester, err)
			SendMessageToUser(generated.UserControlResponseStatus_ERROR, connection, nil)
			continue
		} else if userID != nil {
			logrus.Infoln("Received control message from user", *userID)
		} else {
			logrus.Infoln("Received cintrol request from IP", requester)
		}

		switch control.Status {
		// In case of PUBLIC status - register user
		case generated.UserControlRequestStatus_CONNECTION:
			payload := control.GetConnection()
			status, userID := connectViridian(payload.Token, payload.Address, address.IP)
			logrus.Infoln("Connecting new user", *userID)
			SendMessageToUser(status, connection, userID)
		// In case of HEALTHPING status - update user deletion timer
		case generated.UserControlRequestStatus_HEALTHPING:
			logrus.Infoln("Healthcheck from user", *userID)
			status := updateUser(*userID, control.GetHealthcheck().NextIn)
			SendMessageToUser(status, connection, userID)
		// In case of TERMIN status - delete user record
		case generated.UserControlRequestStatus_DISCONNECTION:
			logrus.Infoln("Deleting user", *userID)
			SendMessageToUser(generated.UserControlResponseStatus_SUCCESS, connection, userID)
			deleteViridian(*userID, false)
		// Default action - send user undefined status
		default:
			logrus.Infof("Unexpected status %v received from user %d", control.Status, *userID)
			SendMessageToUser(generated.UserControlResponseStatus_UNDEFINED, connection, userID)
		}
	}
}

func SendMessageToUser(message any, connection *net.TCPConn, addressee *uint16) {
	var err error
	var payload []byte
	switch value := message.(type) {
	case []byte:
		payload = value
	case *generated.WhirlpoolControlMessage:
		payload, err = proto.Marshal(value)
	case generated.UserControlResponseStatus:
		controlMessage := generated.WhirlpoolControlMessage{Status: value}
		payload, err = proto.Marshal(&controlMessage)
	default:
		controlMessage := generated.WhirlpoolControlMessage{Status: generated.UserControlResponseStatus_ERROR}
		payload, err = proto.Marshal(&controlMessage)
	}
	if err != nil {
		logrus.Errorf("Serializing message error: %v", err)
		return
	}

	encoded, err := Obfuscate(payload, addressee, true)
	if err != nil {
		logrus.Errorf("Sending message to user error: %v", err)
		return
	}

	var encrypted []byte
	if addressee != nil {
		viridian, exists := VIRIDIANS[*addressee]
		if exists {
			encrypted, err = EncryptSymmetrical(encoded, viridian.aead)
			if err != nil {
				logrus.Errorf("Sending message to user error: %v", err)
				return
			}
		}
	}
	if encrypted == nil {
		encrypted = make([]byte, len(encoded))
		if _, err := rand.Read(encrypted); err != nil {
			logrus.Errorf("Sending message to user error: %v", err)
			return
		}
	}

	connection.Write(encrypted)
	connection.Close()
}
