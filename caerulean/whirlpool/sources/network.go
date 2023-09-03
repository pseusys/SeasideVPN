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
	"google.golang.org/protobuf/proto"
)

const (
	RSA_BIT_LENGTH   = 4096
	OWNER_KEY_LENGTH = 32
	AUTORESEED_DELAY = time.Hour * time.Duration(24*3)
)

var (
	RSA_NODE_KEY     *rsa.PrivateKey
	SYMM_NODE_KEY    []byte
	SYMM_NODE_AEAD   cipher.AEAD
	NODE_OWNER_KEY   []byte
	AUTORESEED_TIMER *time.Ticker
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
		writeAndLogError(w, http.StatusBadRequest, "Unable to load RSA node key bytes:", err)
		return
	}

	writeRawData(w, http.StatusOK, publicBytes)
}

func reseed(w http.ResponseWriter, r *http.Request) {
	newNodeKey, err := readFromRequest(r)
	if err != nil {
		writeAndLogError(w, http.StatusBadRequest, "Couldn't read and decrypt reseed request:", err)
		return
	}

	message := &generated.ReseedRequest{}
	err = proto.Unmarshal(newNodeKey, message)
	if err != nil {
		writeAndLogError(w, http.StatusBadRequest, "Couldn't unmarshall reseed request:", err)
		return
	}

	if !bytes.Equal(message.PreviousKey, SYMM_NODE_KEY) {
		writeAndLogError(w, http.StatusBadRequest, "Previous node key doesn't match while reseed:", err)
		return
	}

	newNodeAead, err := chacha20poly1305.NewX(message.NewKey)
	if err != nil {
		writeAndLogError(w, http.StatusBadRequest, "Reseed value can't be used to create symmetric cipher AEAD:", err)
		return
	}

	SYMM_NODE_KEY = message.NewKey
	SYMM_NODE_AEAD = newNodeAead
	logrus.Infof("Symmetric node key reseeded, new value: 0x%x", SYMM_NODE_KEY)
	AUTORESEED_TIMER.Reset(AUTORESEED_DELAY)

	w.WriteHeader(http.StatusOK)
}

func stats(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %q, stats are not available yet :(", html.EscapeString(r.URL.Path))
}

func admin(w http.ResponseWriter, r *http.Request) {
	adminRequest, err := readFromRequest(r)
	if err != nil {
		writeAndLogError(w, http.StatusBadRequest, "Couldn't read and decrypt admin request:", err)
		return
	}

	message := &generated.UserData{}
	err = proto.Unmarshal(adminRequest, message)
	if err != nil {
		writeAndLogError(w, http.StatusBadRequest, "Couldn't unmarshall admin request:", err)
		return
	}

	if !bytes.Equal(message.OwnerKey, NODE_OWNER_KEY) {
		writeAndLogError(w, http.StatusBadRequest, "Owner key doesn't match while admin request:", err)
		return
	}

	token := &generated.UserToken{
		Uid:          message.Uid,
		Session:      message.Session,
		Role:         generated.Role_ADMIN,
		Subscription: nil,
	}
	tokenData, err := proto.Marshal(token)
	if err != nil {
		writeAndLogError(w, http.StatusInternalServerError, "Couldn't marshall admin token:", err)
		return
	}

	tokenEncrypted, err := EncryptSymmetrical(SYMM_NODE_AEAD, tokenData)
	if err != nil {
		writeAndLogError(w, http.StatusInternalServerError, "Couldn't encrypt admin token:", err)
		return
	}

	writeRawData(w, http.StatusOK, tokenEncrypted)
}

func reconn(w http.ResponseWriter, r *http.Request) {
	newNetworkSurface, err := readFromRequest(r)
	if err != nil {
		writeAndLogError(w, http.StatusBadRequest, "Couldn't read and decrypt reconnection request:", err)
		return
	}

	message := &generated.ReconnectionRequest{}
	err = proto.Unmarshal(newNetworkSurface, message)
	if err != nil {
		writeAndLogError(w, http.StatusBadRequest, "Couldn't unmarshall reconnection request:", err)
		return
	}

	if !bytes.Equal(message.OwnerKey, NODE_OWNER_KEY) {
		writeAndLogError(w, http.StatusBadRequest, "Owner key doesn't match while reconnection:", err)
		return
	}

	err = autoReseed()
	if err != nil {
		writeAndLogError(w, http.StatusInternalServerError, "Unable to reseed symmetric node key while reconnecting:", err)
		return
	}

	logrus.Infof("Symmetric node key seeded for reconnection, new value: 0x%x", SYMM_NODE_KEY)
	*surfaceIP = message.NewNetwork
	connectToNetwork(*surfaceIP)
	logrus.Infoln("Requested connection to new network:", *surfaceIP)
	AUTORESEED_TIMER.Reset(AUTORESEED_DELAY)

	w.WriteHeader(http.StatusOK)
}

func InitNetAPI(ip string, port int) {
	logrus.Infoln("Node API setup, node owner key:", string(NODE_OWNER_KEY))

	http.HandleFunc("/public", public)
	http.HandleFunc("/reseed", reseed)
	http.HandleFunc("/stats", stats)
	http.HandleFunc("/admin", admin)
	http.HandleFunc("/reconn", reconn)

	network := fmt.Sprintf("%s:%d", ip, port)
	logrus.Fatalf("Net server error: %s", http.ListenAndServe(network, nil))
}

func writeAndLogError(w http.ResponseWriter, code int, message string, err error) {
	logrus.Errorln(message, err)
	w.Header().Add("Content-Type", "text/plain")
	w.WriteHeader(code)
	w.Write([]byte(message + " " + err.Error()))
}

func writeRawData(w http.ResponseWriter, code int, data []byte) {
	w.Header().Add("Content-Type", "application/octet-stream")
	w.WriteHeader(code)
	w.Write(data)
}

func autoReseed() (err error) {
	newNodeKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(newNodeKey); err != nil {
		return err
	}
	newNodeAead, err := chacha20poly1305.NewX(SYMM_NODE_KEY)
	if err != nil {
		return err
	}
	SYMM_NODE_KEY = newNodeKey
	SYMM_NODE_AEAD = newNodeAead
	return nil
}

func readFromRequest(request *http.Request) ([]byte, error) {
	encryptedBytes := make([]byte, request.ContentLength)
	if _, err := request.Body.Read(encryptedBytes); err != nil {
		return nil, err
	}

	decryptedBytes, err := DecryptRSA(encryptedBytes, RSA_NODE_KEY)
	if err != nil {
		return nil, err
	}
	return decryptedBytes, nil
}

func connectToNetwork(surface string) {
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
	if _, err := publicKeyResp.Body.Read(surfaceKeyBytes); err != nil {
		logrus.Fatalln("Unable to read Surface public key:", err)
	}

	surfaceKey, err := ParsePublicKey(surfaceKeyBytes)
	if err != nil {
		logrus.Fatalln("Unable to parse Surface public key:", err)
	}

	encryptedNodeNetworkKey, err := EncryptRSA(SYMM_NODE_KEY, surfaceKey)
	if err != nil {
		logrus.Fatalln("Unable to encrypt node network key with Surface public key:", err)
	}

	nodeNetworkKeyReader := bytes.NewReader(encryptedNodeNetworkKey)
	connectionSurfaceEndpoint := fmt.Sprintf("%s/connect", surface)
	connectionResp, err := http.Post(connectionSurfaceEndpoint, "application/octet-stream", nodeNetworkKeyReader)
	if err != nil {
		logrus.Fatalln("Unable to post to network Surface:", err)
	}
	if connectionResp.StatusCode != http.StatusOK {
		logrus.Fatalln("Unable to connect to network Surface:", err)
	}
}

func RetrieveNodeKey(surface string) {
	err := autoReseed()
	if err != nil {
		logrus.Fatalln("Unable to seed symmetric node key:", err)
	}
	logrus.Infof("Symmetric node key seeded, value: 0x%x", SYMM_NODE_KEY)

	if surface != NONE_ADDRESS {
		connectToNetwork(surface)
	}

	AUTORESEED_TIMER := time.NewTicker(AUTORESEED_DELAY)
	for range AUTORESEED_TIMER.C {
		err := autoReseed()
		if err != nil {
			logrus.Fatalln("Unable to reseed symmetric node key:", err)
		}
		logrus.Infof("Symmetric node key automatically reseeded, value: 0x%x", SYMM_NODE_KEY)
	}
}
