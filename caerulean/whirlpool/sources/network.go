package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"main/crypto"
	"main/generated"
	"main/utils"
	"net"
	"net/http"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

var (
	NODE_OWNER_KEY string
	PAYLOAD_KEY    string

	AUTH_ENDPOINT string
)

func init() {
	NODE_OWNER_KEY = utils.GetEnv("SEASIDE_PAYLOAD_OWNER")
	PAYLOAD_KEY = utils.GetEnv("SEASIDE_PAYLOAD_USER")

	AUTH_ENDPOINT = utils.GetEnv("SEASIDE_AUTH")
}

func auth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeHttpError(w, fmt.Errorf("method %s not supported", r.Method), http.StatusBadRequest)
		return
	}

	ciphertext, err := io.ReadAll(r.Body)
	if err != nil {
		writeHttpError(w, fmt.Errorf("error reading request bytes: %v", err), http.StatusBadRequest)
		return
	}

	plaintext, err := crypto.Decode(ciphertext, false, crypto.PUBLIC_NODE_AEAD)
	if err != nil {
		writeHttpError(w, fmt.Errorf("error decoding request bytes: %v", err), http.StatusBadRequest)
		return
	}

	message := &generated.UserDataForWhirlpool{}
	err = proto.Unmarshal(plaintext, message)
	if err != nil {
		writeHttpError(w, fmt.Errorf("error unmarshalling message: %v", err), http.StatusBadRequest)
		return
	}

	if message.OwnerKey != NODE_OWNER_KEY {
		writeHttpError(w, errors.New("wrong owner key"), http.StatusBadRequest)
		return
	}

	token := &generated.UserToken{
		Uid:        message.Uid,
		Session:    message.Session,
		Privileged: true,
	}
	marshToken, err := proto.Marshal(token)
	if err != nil {
		writeHttpError(w, fmt.Errorf("error marshalling token: %v", err), http.StatusBadRequest)
		return
	}

	tokenData, err := crypto.Encode(marshToken, nil, crypto.PRIVATE_NODE_AEAD)
	if err != nil {
		writeHttpError(w, fmt.Errorf("error encrypting token: %v", err), http.StatusBadRequest)
		return
	}

	response := &generated.UserCertificate{
		Token:       tokenData,
		UserZero:    int64(crypto.ZERO_USER_ID),
		Multiplier:  int64(crypto.MULTIPLIER),
		SeasidePort: int32(SEASIDE_PORT),
		ControlPort: int32(CONTROL_PORT),
	}
	marshResponse, err := proto.Marshal(response)
	if err != nil {
		writeHttpError(w, fmt.Errorf("error marshalling response: %v", err), http.StatusBadRequest)
		return
	}

	writeHttpData(w, marshResponse)
}

func InitNetAPI(ctx context.Context, port int) {
	logrus.Infof("Node API setup, node owner key: %v", NODE_OWNER_KEY)

	network := fmt.Sprintf("%s:%d", INTERNAL_ADDRESS, port)
	logrus.Debugf("Listening for HTTP requests at: %s", network)
	server := &http.Server{Addr: network, BaseContext: func(net.Listener) context.Context { return ctx }}

	// TODO: distribute stats: http.HandleFunc("/stats", stats)
	http.HandleFunc(fmt.Sprintf("/%s", AUTH_ENDPOINT), auth)
	// TODO: connect to network: http.HandleFunc("/connect", connect)

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Error serving HTTP server: %v", err)
	}
}

func ExchangeNodeKey() {
	var err error
	crypto.PRIVATE_NODE_AEAD, crypto.PRIVATE_NODE_KEY, err = crypto.GenerateCipher()
	if err != nil {
		logrus.Fatalf("Error private node cipher generating: %v", err)
	}

	// TODO: send public and private keys to surface
}
