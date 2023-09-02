package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"html"
	"net/http"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	RSA_BIT_LENGTH   = 4096
	OWNER_KEY_LENGTH = 32
	RAW_DATA_TYPE    = "application/octet-stream"
)

var (
	RSA_NODE_KEY   *rsa.PrivateKey
	SYMM_NODE_KEY  []byte
	SYMM_NODE_AEAD cipher.AEAD
	NODE_OWNER_KEY []byte
)

func init() {
	var err error
	RSA_NODE_KEY, err = rsa.GenerateKey(rand.Reader, RSA_BIT_LENGTH)
	if err != nil {
		logrus.Fatalln("Unable to generate RSA node key:", err)
	}
	NODE_OWNER_KEY, err = RandByteStr(OWNER_KEY_LENGTH)
	if err != nil {
		logrus.Fatalln("Unable to generate node owner key:", err)
	}
}

func public(w http.ResponseWriter, _ *http.Request) {
	publicBytes, err := x509.MarshalPKIXPublicKey(RSA_NODE_KEY.PublicKey)
	if err != nil {
		logrus.Errorln("Unable to load RSA node kry bytes:", err)
	}
	w.Header().Add("Content-Type", RAW_DATA_TYPE)
	w.WriteHeader(http.StatusOK)
	w.Write(publicBytes)
}

func reseed(w http.ResponseWriter, request *http.Request) {
	encryptedReseedBytes := make([]byte, request.ContentLength)
	reseedLength, err := request.Body.Read(encryptedReseedBytes)
	if err != nil {
		logrus.Errorln("Unable to read reseed value:", err)
	}

	reseedBytes, err := DecryptRSA(encryptedReseedBytes, RSA_NODE_KEY)
	if err != nil {
		logrus.Errorln("Unable to decrypt reseed value:", err)
	}
	expectedReseedLength := OWNER_KEY_LENGTH + chacha20poly1305.KeySize
	if len(reseedBytes) != expectedReseedLength {
		logrus.Errorln("Reseed value has unexpected size:", reseedLength)
	}

	ownerKey, newNodeKey := reseedBytes[OWNER_KEY_LENGTH:], reseedBytes[:chacha20poly1305.KeySize]
	if !bytes.Equal(NODE_OWNER_KEY, ownerKey) {
		logrus.Errorln("Reseed value owner key doesn't match node owner key", string(ownerKey))
	} else {
		newNodeAead, err := chacha20poly1305.NewX(newNodeKey)
		if err != nil {
			logrus.Errorln("Reseed value can't be used to create symmetric cipher AEAD:", err)
		} else {
			SYMM_NODE_KEY = newNodeKey
			SYMM_NODE_AEAD = newNodeAead
			logrus.Infof("Symmetric node key reseeded, new value: 0x%x", SYMM_NODE_KEY)
		}
	}
}

func stats(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
}

func admin(w http.ResponseWriter, r *http.Request) {
	// TODO: read user data from request
	// TODO: check node owner key
	// TODO: generate token, encrypt, return
	fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
}

func InitNetAPI(ip string, port int) {
	logrus.Infoln("Node API setup, node owner key:", string(NODE_OWNER_KEY))

	http.HandleFunc("/public", public)
	http.HandleFunc("/reseed", reseed)
	http.HandleFunc("/stats", stats)
	http.HandleFunc("/admin", admin)

	network := fmt.Sprintf("%s:%d", ip, port)
	logrus.Fatalf("Net server error: %s", http.ListenAndServe(network, nil))
}

func RetrieveNodeKey(surface string) {
	if surface == NONE_ADDRESS {
		var err error
		SYMM_NODE_KEY = make([]byte, chacha20poly1305.KeySize)
		if _, err := rand.Read(SYMM_NODE_KEY); err != nil {
			logrus.Fatalln("Unable to generate symmetric node key:", err)
		}
		SYMM_NODE_AEAD, err = chacha20poly1305.NewX(SYMM_NODE_KEY)
		if err != nil {
			logrus.Fatalln("Unable to create symmetric cipher AEAD:", err)
		}
		logrus.Infof("Symmetric node key seeded, value: 0x%x", SYMM_NODE_KEY)
	} else {
		publicKeySurfaceEndpoint := fmt.Sprintf("%s/public", surface)
		publicKeyResp, err := http.Get(publicKeySurfaceEndpoint)
		if err != nil {
			logrus.Fatalln("Unable to get network Surface public key:", err)
		}

		bodySizeExpected := publicKeyResp.ContentLength
		if bodySizeExpected != RSA_BIT_LENGTH {
			logrus.Fatalln("Network Surface response body has unexpected size:", bodySizeExpected)
		}

		surfaceKeyBytes := make([]byte, bodySizeExpected)
		bodySizeActual, err := publicKeyResp.Body.Read(surfaceKeyBytes)
		if err != nil {
			logrus.Fatalln("Unable to read Surface public key:", err)
		}
		if bodySizeExpected != int64(bodySizeActual) {
			logrus.Fatalln("Network Surface public key has unexpected size:", bodySizeExpected)
		}

		surfaceKey, err := ParsePublicKey(surfaceKeyBytes)
		if err != nil {
			logrus.Fatalln("Unable to parse Surface public key:", err)
		}

		encryptedNodeOwnerKey, err := EncryptRSA(NODE_OWNER_KEY, surfaceKey)
		if err != nil {
			logrus.Fatalln("Unable to encrypt node owner key with Surface public key:", err)
		}

		nodeOwnerKeyReader := bytes.NewReader(encryptedNodeOwnerKey)
		connectionSurfaceEndpoint := fmt.Sprintf("%s/connect", surface)
		connectionResp, err := http.Post(connectionSurfaceEndpoint, RAW_DATA_TYPE, nodeOwnerKeyReader)
		if err != nil {
			logrus.Fatalln("Unable to post to network Surface:", err)
		}
		if connectionResp.StatusCode != http.StatusOK {
			logrus.Fatalln("Unable to connect to network Surface:", err)
		}
	}
}
