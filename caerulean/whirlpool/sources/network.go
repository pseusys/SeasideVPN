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
	"golang.org/x/crypto/chacha20poly1305"
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

func auth(w http.ResponseWriter, r *http.Request) {
	// TODO: check POST request
	ciphertext, err := io.ReadAll(r.Body)
	if err != nil {
		WriteAndLogError(w, http.StatusBadRequest, "error reading request bytes", err)
		return
	}

	plaintext, err := crypto.Decode(ciphertext, false, crypto.PUBLIC_NODE_AEAD)
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

	tokenData, err := crypto.Encode(marshToken, nil, crypto.PRIVATE_NODE_AEAD)
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

	responseData, err := crypto.Encode(marshResponse, nil, sessionAEAD)
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
