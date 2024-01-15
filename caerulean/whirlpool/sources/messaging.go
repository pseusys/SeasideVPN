package main

import (
	"main/crypto"
	"main/generated"
	"net"
	"net/http"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func writeHttpResponse(w http.ResponseWriter, data []byte, code int) {
	w.Header().Add("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	w.Write(data)
}

func writeHttpData(w http.ResponseWriter, data []byte) {
	encrypted, err := crypto.Encode(data, nil, crypto.PUBLIC_NODE_AEAD)
	if err != nil {
		writeHttpResponse(w, nil, http.StatusInternalServerError)
		logrus.Warnf("Error encoding HTTP response: %v (%v)", err, data)
	} else {
		writeHttpResponse(w, encrypted, http.StatusOK)
	}
}

func writeHttpError(w http.ResponseWriter, message error, code int) {
	data, err := crypto.Encode([]byte(message.Error()), nil, crypto.PUBLIC_NODE_AEAD)
	if err != nil {
		writeHttpResponse(w, nil, http.StatusInternalServerError)
		logrus.Warnf("Error encoding HTTP response: %v (%v)", err, message)
	} else {
		writeHttpResponse(w, data, code)
		logrus.Warnf("Sending error by HTTP: %v", message)
	}
}

func sendMessageToSocket(status generated.ControlResponseStatus, message error, connection *net.TCPConn, addressee *uint16) {
	byteMessage := ""
	if message != nil {
		if addressee != nil {
			logrus.Warnf("Sending error to viridian %d: %v", addressee, message)
		} else {
			logrus.Warnf("Sending error to IP %v: %v", connection.RemoteAddr(), message)
		}
		byteMessage = message.Error()
	}

	controlMessage := generated.ControlResponse{Status: status, Message: byteMessage}
	payload, err := proto.Marshal(&controlMessage)
	if err != nil {
		logrus.Errorf("Error serializing message: %v", err)
		return
	}

	encrypted, err := crypto.Encrypt(payload, crypto.PUBLIC_NODE_AEAD, addressee, true)
	if err != nil {
		logrus.Errorf("Error sending message to user: %v", err)
		return
	}

	connection.Write(encrypted)
	connection.Close()
}
