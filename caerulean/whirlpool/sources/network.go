package main

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"main/crypto"
	"main/generated"
	"main/utils"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
)

const (
	NODE_NAME        = "Node name TODO: pass through env"
	OWNER_KEY_LENGTH = 32
	AUTORESEED_DELAY = time.Hour * time.Duration(24)
)

var (
	NODE_OWNER_KEY   string
	AUTORESEED_TIMER *time.Ticker
)

func public(w http.ResponseWriter, r *http.Request) {
	// TODO: check GET request
	publicBytes, err := x509.MarshalPKIXPublicKey(&(crypto.RSA_NODE_KEY.PublicKey))
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error loading RSA node key bytes", err)
		return
	}

	WriteRawData(w, http.StatusOK, publicBytes)
}

func auth(w http.ResponseWriter, r *http.Request) {
	// TODO: check POST request
	ciphertext, err := io.ReadAll(r.Body)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error reading request bytes", err)
		return
	}

	plaintext, err := crypto.DecodeRSA(ciphertext, false, crypto.RSA_NODE_KEY)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error decoding temp key", err)
		return
	}

	message := &generated.UserDataWhirlpool{}
	err = proto.Unmarshal(plaintext, message)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error unmarshalling message", err)
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
	marshToken, err := proto.Marshal(token)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error marshalling token", err)
		return
	}

	tokenData, err := crypto.EncodeSymmetrical(marshToken, nil, crypto.SYMM_NODE_AEAD)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error encrypting token", err)
		return
	}

	response := &generated.UserCertificate{
		Token:       tokenData,
		UserZero:    int64(crypto.ZERO_USER_ID),
		Multiplier:  int64(crypto.MULTIPLIER),
		SeaPort:     int32(*port),
		ControlPort: int32(*control),
	}
	marshResponse, err := proto.Marshal(response)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error marshalling response", err)
		return
	}

	responseData, err := crypto.EncodeSymmetrical(marshResponse, nil, sessionAEAD)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error encrypting response", err)
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
		return utils.JoinError("error creating new node symmetric key", err)
	}
	newNodeAead, err := chacha20poly1305.NewX(newNodeKey)
	if err != nil {
		return utils.JoinError("error creating new node symmetric cipher", err)
	}

	crypto.SYMM_NODE_KEY = newNodeKey
	crypto.SYMM_NODE_AEAD = newNodeAead
	logrus.Infof("Symmetric node key seeded, value: 0x%x", crypto.SYMM_NODE_KEY)
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
