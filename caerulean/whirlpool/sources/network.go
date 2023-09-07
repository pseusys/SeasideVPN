package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"html"
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
	USER_ID          = []byte("User id TODO: pass through env")
	RSA_NODE_KEY     *rsa.PrivateKey
	SYMM_NODE_KEY    []byte
	SYMM_NODE_AEAD   cipher.AEAD
	NODE_OWNER_KEY   string
	AUTORESEED_TIMER *time.Ticker
	IS_PREMIUM       = false
)

func init() {
	var err error
	RSA_NODE_KEY, err = rsa.GenerateKey(rand.Reader, RSA_BIT_LENGTH)
	if err != nil {
		logrus.Fatalln("error generating RSA node key:", err)
	}
	NODE_OWNER_KEY, err = RandByteStr(OWNER_KEY_LENGTH)
	if err != nil {
		logrus.Fatalln("error generating node owner key:", err)
	}
}

func public(w http.ResponseWriter, _ *http.Request) {
	publicBytes, err := x509.MarshalPKIXPublicKey(RSA_NODE_KEY.PublicKey)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error loading RSA node key bytes", err)
		return
	}

	WriteRawData(w, http.StatusOK, publicBytes)
}

func stats(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %q, stats are not available yet :(", html.EscapeString(r.URL.Path))
}

func auth(w http.ResponseWriter, r *http.Request) {
	message := &generated.UserDataWhirlpool{}
	err := UnmarshalDecrypting(r, RSA_NODE_KEY, message)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error processing auth request", err)
		return
	}

	sessionAEAD, err := chacha20poly1305.NewX(message.Session)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error creating session cipher", err)
		return
	}

	token := &generated.UserToken{
		Uid:         message.Uid,
		Session:     message.Session,
		FromNetwork: false,
	}
	if message.OwnerKey != nil && *message.OwnerKey == NODE_OWNER_KEY {
		token.Role = generated.Role_ADMIN
		token.OwnerKey = &NODE_OWNER_KEY
	} else {
		token.Role = generated.Role_FREE
	}
	tokenData, err := MarshalEncrypting(SYMM_NODE_AEAD, token)
	if err != nil {
		WriteAndLogError(w, http.StatusInternalServerError, "error processing admin token", err)
		return
	}

	response := &generated.UserCertificate{
		Token:       tokenData,
		SeaPort:     int32(*port),
		ControlPort: int32(*control),
	}
	responseData, err := MarshalEncrypting(sessionAEAD, response)
	if err != nil {
		WriteAndLogError(w, http.StatusInternalServerError, "error processing admin response", err)
		return
	}

	WriteRawData(w, http.StatusOK, responseData)
}

func connect(w http.ResponseWriter, r *http.Request) {
	message := &generated.ReconnectionRequest{}
	err := UnmarshalDecrypting(r, RSA_NODE_KEY, message)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error processing reconnection request", err)
		return
	}

	if message.OwnerKey != NODE_OWNER_KEY {
		WriteAndLogError(w, http.StatusBadRequest, "owner key doesn't match", err)
		return
	}

	logrus.Infof("Symmetric node key seeded for reconnection, new value: 0x%x", SYMM_NODE_KEY)
	newNetwork := message.NewNetwork

	if newNetwork == NONE_ADDRESS {
		logrus.Infoln("Network connection disabled")
	} else {
		logrus.Infoln("Requested connection to new network:", newNetwork)
		// TODO: disconnect all network users.
	}

	err = reseedAndReconnect(newNetwork)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error reseeding node key", err)
		return
	} else {
		AUTORESEED_TIMER.Reset(AUTORESEED_DELAY)
	}

	*surfaceIP = newNetwork
	w.WriteHeader(http.StatusOK)
}

func InitNetAPI(ip string, port int) {
	logrus.Infoln("Node API setup, node owner key:", NODE_OWNER_KEY)

	http.HandleFunc("/public", public)
	http.HandleFunc("/stats", stats)
	http.HandleFunc("/auth", auth)
	http.HandleFunc("/connect", connect)

	network := fmt.Sprintf("%s:%d", ip, port)
	logrus.Fatalf("Net server error: %s", http.ListenAndServe(network, nil))
}

func connectToNetwork(surface string) (bool, error) {
	publicKeySurfaceEndpoint := fmt.Sprintf("%s/public", surface)
	publicKeyResp, err := http.Get(publicKeySurfaceEndpoint)
	if err != nil || publicKeyResp.StatusCode != http.StatusOK {
		return false, JoinError("unable to get network surface public key", err, publicKeyResp.StatusCode)
	}

	surfaceKey, err := ReadRSAKeyFromRequest(&publicKeyResp.Body, publicKeyResp.ContentLength)
	if err != nil {
		return false, JoinError("unable to parse surface public key", err)
	}

	connectionRequest := &generated.ConnectionRequest{
		UserId:       USER_ID,
		NodeName:     NODE_NAME,
		NodeKey:      SYMM_NODE_KEY,
		NodeCapacity: int32(*max_users),
		SeaPort:      int32(*port),
		ControlPort:  int32(*control),
	}
	marshRequest, err := MarshalEncrypting(surfaceKey, connectionRequest)
	if err != nil {
		return false, JoinError("unable to marshal connection request", err)
	}

	nodeNetworkKeyReader := bytes.NewReader(marshRequest)
	connectionSurfaceEndpoint := fmt.Sprintf("%s/connect", surface)
	connectionResp, err := http.Post(connectionSurfaceEndpoint, "application/octet-stream", nodeNetworkKeyReader)
	if err != nil || connectionResp.StatusCode != http.StatusOK {
		return false, JoinError("error connecting to network surface", err, connectionResp.StatusCode)
	}

	message := &generated.ConnectionResponse{}
	err = UnmarshalDecrypting(connectionResp, RSA_NODE_KEY, message)
	if err != nil {
		return false, JoinError("error decrypting connection response", err)
	}

	return message.IsPremium, nil
}

func reseedAndReconnect(surface string) error {
	newNodeKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(newNodeKey); err != nil {
		return JoinError("error creating new node symmetric key", err)
	}
	newNodeAead, err := chacha20poly1305.NewX(SYMM_NODE_KEY)
	if err != nil {
		return JoinError("error creating new node symmetric cipher", err)
	}

	var newIsPremium = false
	if surface != NONE_ADDRESS {
		newIsPremium, err = connectToNetwork(surface)
		if err == nil {
			logrus.Infoln("Connected to network with Surface node on:", surface)
		} else {
			logrus.Errorf("Network Surface %s connection error: %v", surface, err)
		}
	} else {
		logrus.Infoln("No connection to any network requested")
	}

	if newIsPremium && !IS_PREMIUM {
		// TODO: disconnect all free users.
	} else if !newIsPremium && IS_PREMIUM {
		// TODO: disable timers for all premium userss
	}

	IS_PREMIUM = newIsPremium
	logrus.Infof("Node has declared itself as premium: %t", IS_PREMIUM)
	SYMM_NODE_KEY = newNodeKey
	SYMM_NODE_AEAD = newNodeAead
	logrus.Infof("Symmetric node key seeded, value: 0x%x", SYMM_NODE_KEY)
	return nil
}

func RetrieveNodeKey() {
	reseedAndReconnect(*surfaceIP)

	AUTORESEED_TIMER := time.NewTicker(AUTORESEED_DELAY)
	for range AUTORESEED_TIMER.C {
		reseedAndReconnect(*surfaceIP)
	}
}
