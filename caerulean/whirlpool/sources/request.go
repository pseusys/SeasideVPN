package main

import (
	"crypto/cipher"
	"crypto/rsa"
	"io"
	"net/http"
	"reflect"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func UnmarshalDecrypting(source any, key any, message proto.Message, decode bool) (err error) {
	var encryptedBytes []byte
	switch value := source.(type) {
	case []byte:
		encryptedBytes = value
	case *http.Request:
		encryptedBytes, err = io.ReadAll(value.Body)
		if err != nil {
			return JoinError("error reading request bytes", err)
		}
	case *http.Response:
		encryptedBytes, err = io.ReadAll(value.Body)
		if err != nil {
			return JoinError("error reading response bytes", err)
		}
	default:
		return JoinError("unexpected data source", reflect.TypeOf(source))
	}

	var decryptedBytes []byte
	switch value := key.(type) {
	case cipher.AEAD:
		decryptedBytes, err = DecryptSymmetrical(encryptedBytes, value)
	case *rsa.PrivateKey:
		decryptedBytes, err = DecryptBlockRSA(encryptedBytes, value)
	default:
		return JoinError("unexpected cipher type", reflect.TypeOf(key))
	}

	if err != nil {
		return JoinError("error decrypting request bytes", err)
	}

	var decodedBytes []byte
	if decode {
		decodedBytes, err = DecodeMessage(decryptedBytes)
		if err != nil {
			return JoinError("error decoding request bytes", err)
		}
	} else {
		decodedBytes = decryptedBytes
	}

	err = proto.Unmarshal(decodedBytes, message)
	if err != nil {
		return JoinError("error unmarshalling request message", err)
	}

	return nil
}

func MarshalEncrypting(key any, message protoreflect.ProtoMessage, encode bool) ([]byte, error) {
	marshRequest, err := proto.Marshal(message)
	if err != nil {
		return nil, JoinError("error marshalling message", err)
	}

	var encodedBytes []byte
	if encode {
		encodedBytes, err = EncodeMessage(marshRequest, true)
		if err != nil {
			return nil, JoinError("error encoding message bytes", err)
		}
	} else {
		encodedBytes = marshRequest
	}

	var encryptedRequest []byte
	switch value := key.(type) {
	case cipher.AEAD:
		encryptedRequest, err = EncryptSymmetrical(encodedBytes, value)
	case *rsa.PublicKey:
		encryptedRequest, err = EncryptRSA(encodedBytes, value)
	default:
		return nil, JoinError("unexpected cipher type", reflect.TypeOf(key))
	}

	if err != nil {
		return nil, JoinError("error encrypting message bytes", err)
	}

	return encryptedRequest, nil
}

func WriteAndLogError(w http.ResponseWriter, code int, message string, err error) {
	w.Header().Add("Content-Type", "text/plain")
	w.WriteHeader(code)
	if err != nil {
		logrus.Errorln(message, err)
		w.Write([]byte(JoinError(message, err).Error()))
	} else {
		logrus.Errorln(message)
		w.Write([]byte(message))
	}
}

func WriteRawData(w http.ResponseWriter, code int, data []byte) {
	w.Header().Add("Content-Type", "application/octet-stream")
	w.WriteHeader(code)
	w.Write(data)
}
