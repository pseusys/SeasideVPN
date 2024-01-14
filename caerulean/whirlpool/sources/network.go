package main

import (
	"fmt"
	"io"
	"main/crypto"
	"main/generated"
	"main/utils"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	NODE_NAME        = "Node name TODO: pass through env"
	AUTORESEED_DELAY = time.Hour * time.Duration(24)
)

var (
	NODE_OWNER_KEY   string
	AUTORESEED_TIMER *time.Ticker
)

func init() {
	NODE_OWNER_KEY = utils.GetEnv("OWNER_KEY", nil)
}

func writeRawData(w http.ResponseWriter, data []byte, code int) {
	w.Header().Add("Content-Type", "application/octet-stream")
	w.WriteHeader(code)
	w.Write(data)
}

func auth(w http.ResponseWriter, r *http.Request) {
	// TODO: check POST request
	ciphertext, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("error reading request bytes: %v", err), http.StatusBadRequest)
		return
	}

	plaintext, err := crypto.Decode(ciphertext, false, crypto.PUBLIC_NODE_AEAD)
	if err != nil {
		http.Error(w, fmt.Sprintf("error decoding temp key: %v", err), http.StatusBadRequest)
		return
	}

	message := &generated.UserDataWhirlpool{}
	err = proto.Unmarshal(plaintext, message)
	if err != nil {
		http.Error(w, fmt.Sprintf("error unmarshalling message: %v", err), http.StatusBadRequest)
		return
	}

	if message.OwnerKey != NODE_OWNER_KEY {
		http.Error(w, "wrong owner key", http.StatusBadRequest)
		return
	}

	token := &generated.UserToken{
		Uid:        message.Uid,
		Session:    message.Session,
		Privileged: true,
	}
	marshToken, err := proto.Marshal(token)
	if err != nil {
		http.Error(w, fmt.Sprintf("error marshalling token: %v", err), http.StatusBadRequest)
		return
	}

	tokenData, err := crypto.Encode(marshToken, nil, crypto.PRIVATE_NODE_AEAD)
	if err != nil {
		http.Error(w, fmt.Sprintf("error encrypting token: %v", err), http.StatusBadRequest)
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
		http.Error(w, fmt.Sprintf("error marshalling response: %v", err), http.StatusBadRequest)
		return
	}

	responseData, err := crypto.Encode(marshResponse, nil, crypto.PUBLIC_NODE_AEAD)
	if err != nil {
		http.Error(w, fmt.Sprintf("error encrypting response: %v", err), http.StatusBadRequest)
		return
	}

	writeRawData(w, responseData, http.StatusOK)
}

func InitNetAPI(port int) {
	if NODE_OWNER_KEY == NONE_ARG {
		logrus.Fatalln("owner key not provided")
	} else {
		logrus.Infoln("Node API setup, node owner key:", NODE_OWNER_KEY)
	}

	// TODO: distribute stats: http.HandleFunc("/stats", stats)
	http.HandleFunc("/auth", auth)
	// TODO: connect to network: http.HandleFunc("/connect", connect)

	network := fmt.Sprintf("%s:%d", *iIP, port)
	logrus.Infoln("Listening for HTTP requests at:", network)
	logrus.Fatalf("Net server error: %s", http.ListenAndServe(network, nil))
}

func ExchangeNodeKey() {
	var err error
	crypto.PRIVATE_NODE_AEAD, crypto.PRIVATE_NODE_KEY, err = crypto.GenerateCipher()
	if err != nil {
		logrus.Fatalf("error private node cipher generating: %v", err)
	}

	// TODO: send public and private keys to surface
}
