package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"main/m/v2/generated"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	NODE_NAME        = "Node name TODO: pass through env"
	RSA_BIT_LENGTH   = 4096
	OWNER_KEY_LENGTH = 32
	AUTORESEED_DELAY = time.Hour * time.Duration(24)
)

var (
	RSA_NODE_KEY     *rsa.PrivateKey
	SYMM_NODE_KEY    []byte
	SYMM_NODE_AEAD   cipher.AEAD
	NODE_OWNER_KEY   string
	AUTORESEED_TIMER *time.Ticker
)

func init() {
	var err error
	RSA_NODE_KEY, err = rsa.GenerateKey(rand.Reader, RSA_BIT_LENGTH)
	if err != nil {
		logrus.Fatalln("error generating RSA node key:", err)
	}
}

func public(w http.ResponseWriter, _ *http.Request) {
	// TODO: check GET request
	publicBytes, err := x509.MarshalPKIXPublicKey(&(RSA_NODE_KEY.PublicKey))
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error loading RSA node key bytes", err)
		return
	}

	publicEncoded, err := EncodeMessage(publicBytes, false)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error encoding RSA node key bytes", err)
		return
	}

	WriteRawData(w, http.StatusOK, publicEncoded)
}

func auth(w http.ResponseWriter, r *http.Request) {
	// TODO: check POST request
	message := &generated.UserDataWhirlpool{}
	err := UnmarshalDecrypting(r, RSA_NODE_KEY, message, true)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error processing auth request", err)
		return
	}

	sessionAEAD, err := chacha20poly1305.NewX(message.Session)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error creating session cipher", err)
		return
	}

	if message.OwnerKey != NODE_OWNER_KEY {
		WriteAndLogError(w, http.StatusBadRequest, "wrong owner key", nil)
		return
	}

	token := &generated.UserToken{
		Uid:        message.Uid,
		Session:    message.Session,
		Privileged: true,
	}
	tokenData, err := MarshalEncrypting(SYMM_NODE_AEAD, token, false)
	if err != nil {
		WriteAndLogError(w, http.StatusInternalServerError, "error processing admin token", err)
		return
	}

	response := &generated.UserCertificate{
		Token:       tokenData,
		SeaPort:     int32(*port),
		ControlPort: int32(*control),
	}
	responseData, err := MarshalEncrypting(sessionAEAD, response, true)
	if err != nil {
		WriteAndLogError(w, http.StatusInternalServerError, "error processing admin response", err)
		return
	}

	WriteRawData(w, http.StatusOK, responseData)
}

func InitNetAPI(port int) {
	if NODE_OWNER_KEY == NONE_ARG {
		logrus.Fatalln("owner key not provided")
	} else {
		logrus.Infoln("Node API setup, node owner key:", NODE_OWNER_KEY)
	}

	http.HandleFunc("/public", public)
	// TODO: distribute stats: http.HandleFunc("/stats", stats)
	http.HandleFunc("/auth", auth)
	// TODO: connect to network: http.HandleFunc("/connect", connect)

	network := fmt.Sprintf("%s:%d", *iIP, port)
	logrus.Infoln("Listening for HTTP requests at:", network)
	logrus.Fatalf("Net server error: %s", http.ListenAndServe(network, nil))
}

func reseed(surface string) error {
	newNodeKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(newNodeKey); err != nil {
		return JoinError("error creating new node symmetric key", err)
	}
	newNodeAead, err := chacha20poly1305.NewX(newNodeKey)
	if err != nil {
		return JoinError("error creating new node symmetric cipher", err)
	}

	SYMM_NODE_KEY = newNodeKey
	SYMM_NODE_AEAD = newNodeAead
	logrus.Infof("Symmetric node key seeded, value: 0x%x", SYMM_NODE_KEY)
	return nil
}

func RetrieveNodeKey() {
	err := reseed(*surfaceIP)
	if err != nil {
		logrus.Fatalln("error initial cipher seeding", err)
	}

	AUTORESEED_TIMER := time.NewTicker(AUTORESEED_DELAY)
	for range AUTORESEED_TIMER.C {
		reseed(*surfaceIP)
	}
}
