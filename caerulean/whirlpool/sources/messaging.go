package main

import (
	"bytes"
	"fmt"
	"io"
	"main/crypto"
	"main/generated"
	"net"
	"net/http"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func readHttpRequest(w http.ResponseWriter, r *http.Request, message protoreflect.ProtoMessage) error {
	ciphertext, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("error reading request bytes: %v", err)
	}

	plaintext, err := crypto.Decode(ciphertext, false, crypto.PUBLIC_NODE_AEAD)
	if err != nil {
		return fmt.Errorf("error decoding request bytes: %v", err)
	}

	err = proto.Unmarshal(plaintext, message)
	if err != nil {
		return fmt.Errorf("error unmarshalling message: %v", err)
	}

	return nil
}

func writeHttpResponse(w http.ResponseWriter, data []byte, code int) {
	w.Header().Add("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	w.Write(data)
}

func writeHttpData(w http.ResponseWriter, message protoreflect.ProtoMessage) {
	marshMessage, err := proto.Marshal(message)
	if err != nil {
		writeHttpError(w, fmt.Errorf("error marshalling response: %v", err), http.StatusInternalServerError)
		return
	}

	encrypted, err := crypto.Encode(marshMessage, nil, crypto.PUBLIC_NODE_AEAD)
	if err != nil {
		writeHttpError(w, fmt.Errorf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}

	writeHttpResponse(w, encrypted, http.StatusOK)
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

func readMessageFromSocket(connection *net.TCPConn, buffer bytes.Buffer, requester string, message protoreflect.ProtoMessage) (*uint16, error) {
	r, err := io.Copy(&buffer, connection)
	if err != nil {
		return nil, fmt.Errorf("error reading control message (%d bytes read): %v", r, err)
	}

	plaintext, userID, err := crypto.Decrypt(buffer.Bytes(), crypto.PUBLIC_NODE_AEAD, true)
	if err != nil {
		return nil, fmt.Errorf("error decrypting message from IP %v: %v", requester, err)
	}

	err = proto.Unmarshal(plaintext, message)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling request from IP %v: %v", requester, err)
	}

	return userID, nil
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
