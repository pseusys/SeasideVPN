package main

import (
	"crypto/cipher"
	"crypto/rsa"
	"io"
	"main/crypto"
	"main/utils"
	"net/http"
	"reflect"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func UnmarshalDecrypting(source any, key any, message proto.Message, decode bool) (userID *uint16, err error) {
	var encryptedBytes []byte
	switch value := source.(type) {
	case []byte:
		encryptedBytes = value
	case *http.Request:
		encryptedBytes, err = io.ReadAll(value.Body)
		if err != nil {
			return nil, utils.JoinError("error reading request bytes", err)
		}
	case *http.Response:
		encryptedBytes, err = io.ReadAll(value.Body)
		if err != nil {
			return nil, utils.JoinError("error reading response bytes", err)
		}
	default:
		return nil, utils.JoinError("unexpected data source", reflect.TypeOf(source))
	}

	var decryptedBytes []byte
	switch value := key.(type) {
	case cipher.AEAD:
		decryptedBytes, err = crypto.DecryptSymmetrical(encryptedBytes, value)
	case *rsa.PrivateKey:
		decryptedBytes, err = crypto.DecryptRSA(encryptedBytes, value)
	default:
		return nil, utils.JoinError("unexpected cipher type", reflect.TypeOf(key))
	}

	if err != nil {
		return nil, utils.JoinError("error decrypting request bytes", err)
	}

	var decodedBytes []byte
	if decode {
		decodedBytes, userID, err = crypto.Deobfuscate(decryptedBytes, true)
		if err != nil {
			return nil, utils.JoinError("error decoding request bytes", err)
		}
	} else {
		decodedBytes = decryptedBytes
	}

	err = proto.Unmarshal(decodedBytes, message)
	if err != nil {
		return nil, utils.JoinError("error unmarshalling request message", err)
	}

	return userID, nil
}

func MarshalEncrypting(key any, message protoreflect.ProtoMessage, encode bool) ([]byte, error) {
	marshRequest, err := proto.Marshal(message)
	if err != nil {
		return nil, utils.JoinError("error marshalling message", err)
	}

	var encodedBytes []byte
	if encode {
		encodedBytes, err = crypto.Obfuscate(marshRequest, nil, true)
		if err != nil {
			return nil, utils.JoinError("error encoding message bytes", err)
		}
	} else {
		encodedBytes = marshRequest
	}

	var encryptedRequest []byte
	switch value := key.(type) {
	case cipher.AEAD:
		encryptedRequest, err = crypto.EncryptSymmetrical(encodedBytes, value)
	case *rsa.PublicKey:
		encryptedRequest, err = crypto.EncryptRSA(encodedBytes, value)
	default:
		return nil, utils.JoinError("unexpected cipher type", reflect.TypeOf(key))
	}

	if err != nil {
		return nil, utils.JoinError("error encrypting message bytes", err)
	}

	return encryptedRequest, nil
}

func WriteAndLogError(w http.ResponseWriter, code int, message string, err error) {
	w.Header().Add("Content-Type", "text/plain")
	w.WriteHeader(code)
	if err != nil {
		logrus.Errorln(message, err)
		w.Write([]byte(utils.JoinError(message, err).Error()))
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
