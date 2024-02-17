package main

import (
	"bytes"
	"crypto/rand"
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

// Maximum random bytes tail length.
const MAX_TAIL_LENGTH = 64

// Helper function, read protobuf message from HTTP request, decode it with public key and unmarshall.
// Accept HTTP request and pointer to expected message container.
// Return error if an error happens on any step, nil otherwise.
func readHttpRequest(r *http.Request, message protoreflect.ProtoMessage) error {
	// Read message from request body
	ciphertext, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("error reading request bytes: %v", err)
	}

	// Decode message with public node key
	plaintext, err := crypto.Decode(ciphertext, crypto.PUBLIC_NODE_AEAD)
	if err != nil {
		return fmt.Errorf("error decoding request bytes: %v", err)
	}

	// Unmarshall message into container
	err = proto.Unmarshal(plaintext, message)
	if err != nil {
		return fmt.Errorf("error unmarshalling message: %v", err)
	}

	// Return no error
	return nil
}

// Helper function, write data and code as HTTP response.
// Accept response writer, data to write and HTTP code.
func writeHttpResponse(w http.ResponseWriter, data []byte, code int) {
	w.Header().Add("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	w.Write(data)
}

// Helper function, marshall protobuf message, encode it with public key and write as HTTP response.
// If an error occurs on any step, error message and code are sent instead.
// Accept response writer and message pointer.
func writeHttpData(w http.ResponseWriter, message protoreflect.ProtoMessage) {
	// Marshall the message
	marshMessage, err := proto.Marshal(message)
	if err != nil {
		writeHttpError(w, fmt.Errorf("error marshalling response: %v", err), http.StatusInternalServerError)
		return
	}

	// Encode the message with public key
	encrypted, err := crypto.Encode(marshMessage, crypto.PUBLIC_NODE_AEAD)
	if err != nil {
		writeHttpError(w, fmt.Errorf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}

	// Write the response
	writeHttpResponse(w, encrypted, http.StatusOK)
}

// Helper function, encode an error with public key and write it as HTTP response.
// Accept response writer, error to write and HTTP code.
func writeHttpError(w http.ResponseWriter, message error, code int) {
	data, err := crypto.Encode([]byte(message.Error()), crypto.PUBLIC_NODE_AEAD)
	if err != nil {
		writeHttpResponse(w, nil, http.StatusInternalServerError)
		logrus.Warnf("Error encoding HTTP response: %v (%v)", err, message)
	} else {
		writeHttpResponse(w, data, code)
		logrus.Warnf("Sending error by HTTP: %v", message)
	}
}

// Helper function, read protobuf message from TCP socket, decrypt it with node public key and and unmarshall.
// Accept TCP connection, buffer for reading (should be resetted after each use), requester IP address (as a string) and a pointer to expected message container.
// Return sender user ID pointer if no error occurs, nil and error otherwise.
func readMessageFromSocket(connection *net.TCPConn, buffer bytes.Buffer, requester string, message protoreflect.ProtoMessage) (*uint16, error) {
	// Copy message from connection to buffer
	r, err := io.Copy(&buffer, connection)
	if err != nil {
		return nil, fmt.Errorf("error reading control message (%d bytes read): %v", r, err)
	}

	// Decrypt message
	plaintext, userID, err := crypto.Decrypt(buffer.Bytes(), crypto.PUBLIC_NODE_AEAD, true)
	if err != nil {
		return nil, fmt.Errorf("error decrypting message from IP %v: %v", requester, err)
	}

	// Unmarshall message
	err = proto.Unmarshal(plaintext, message)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling request from IP %v: %v", requester, err)
	}

	// Return user ID and no error
	return userID, nil
}

// Helper function, enrypt an error with public key and write it to a TCP socket.
// Accept ControlResponseStatus to write, error to write, TCP connection to use and viridian IP address pointer.
// If no error should be written, error should be nil.
// If message is sent successfully, connection will be closed.
func sendMessageToSocket(status generated.ControlResponseStatus, message error, connection *net.TCPConn, addressee *uint16) {
	// Log error if it is not nil
	byteMessage := ""
	if message != nil {
		if addressee != nil {
			logrus.Warnf("Sending error to viridian %d: %v", *addressee, message)
		} else {
			logrus.Warnf("Sending error to IP %v: %v", connection.RemoteAddr(), message)
		}
		byteMessage = message.Error()
	}

	// Read random tail bytes
	tail := make([]byte, MAX_TAIL_LENGTH)
	if _, err := rand.Read(tail); err != nil {
		logrus.Errorf("tail reading error: %v", err)
		return
	}

	// Create ControlResponse protobuf message
	controlMessage := generated.ControlResponse{Status: status, Message: byteMessage, Tail: tail}
	payload, err := proto.Marshal(&controlMessage)
	if err != nil {
		logrus.Errorf("Error serializing message: %v", err)
		return
	}

	// Encrypt response message
	encrypted, err := crypto.Encrypt(payload, crypto.PUBLIC_NODE_AEAD, addressee, true)
	if err != nil {
		logrus.Errorf("Error sending message to user: %v", err)
		return
	}

	// Write and close the connection
	connection.Write(encrypted)
	connection.Close()
}
