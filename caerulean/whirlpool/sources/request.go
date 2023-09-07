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

func UnmarshalDecrypting(requestBody *io.ReadCloser, contentLength int64, key any, message proto.Message) error {
	encryptedBytes := make([]byte, contentLength)
	if _, err := (*requestBody).Read(encryptedBytes); err != nil {
		return JoinError("error reading request bytes", err)
	}

	var err error
	var decryptedBytes []byte
	switch value := key.(type) {
	case cipher.AEAD:
		decryptedBytes, err = EncryptSymmetrical(encryptedBytes, value)
	case *rsa.PublicKey:
		decryptedBytes, err = EncryptRSA(encryptedBytes, value)
	default:
		return JoinError("unexpected cipher type", reflect.TypeOf(key))
	}

	if err != nil {
		return JoinError("error decrypting request bytes", err)
	}

	err = proto.Unmarshal(decryptedBytes, message)
	if err != nil {
		return JoinError("error unmarshalling request message", err)
	}

	return nil
}

func MarshalEncrypting(key interface{}, message protoreflect.ProtoMessage) ([]byte, error) {
	marshRequest, err := proto.Marshal(message)
	if err != nil {
		return nil, JoinError("error marshalling message", err)
	}

	var encryptedRequest []byte
	switch value := key.(type) {
	case cipher.AEAD:
		encryptedRequest, err = EncryptSymmetrical(marshRequest, value)
	case *rsa.PublicKey:
		encryptedRequest, err = EncryptRSA(marshRequest, value)
	default:
		return nil, JoinError("unexpected cipher type", reflect.TypeOf(key))
	}

	if err != nil {
		return nil, JoinError("error encrypting message bytes", err)
	}
	return encryptedRequest, nil
}

func ReadRSAKeyFromRequest(requestBody *io.ReadCloser, contentLength int64) (*rsa.PublicKey, error) {
	bodySizeExpected := contentLength
	if bodySizeExpected != RSA_BIT_LENGTH {
		return nil, JoinError("wrong RSA key length", bodySizeExpected)
	}

	surfaceKeyBytes := make([]byte, bodySizeExpected)
	if _, err := (*requestBody).Read(surfaceKeyBytes); err != nil {
		return nil, JoinError("error reading request RSA key bytes", err)
	}

	surfaceKey, err := ParsePublicKey(surfaceKeyBytes)
	if err != nil {
		return nil, JoinError("error parsing RSA key", err)
	}

	return surfaceKey, nil
}

func WriteAndLogError(w http.ResponseWriter, code int, message string, err error) {
	logrus.Errorln(message, err)
	w.Header().Add("Content-Type", "text/plain")
	w.WriteHeader(code)
	w.Write([]byte(JoinError(message, err).Error()))
}

func WriteRawData(w http.ResponseWriter, code int, data []byte) {
	w.Header().Add("Content-Type", "application/octet-stream")
	w.WriteHeader(code)
	w.Write(data)
}

func IsResponseCodeSuccessful(response *http.Response) bool {
	return response.StatusCode/100 == 2
}
