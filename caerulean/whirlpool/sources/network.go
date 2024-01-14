package main

import (
	"fmt"
	"io"
	"main/crypto"
	"main/generated"
	"main/utils"
	"net/http"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

var (
	NODE_OWNER_KEY string
	PAYLOAD_KEY    string

	NAUTICHART_ENDPOINT string
	AUTH_ENDPOINT       string
)

func init() {
	NODE_OWNER_KEY = utils.GetEnv("SEASIDE_PAYLOAD_OWNER", nil)
	PAYLOAD_KEY = utils.GetEnv("SEASIDE_PAYLOAD_USER", nil)

	NAUTICHART_ENDPOINT = utils.GetEnv("SEASIDE_NAUTICHART", nil)
	AUTH_ENDPOINT = utils.GetEnv("SEASIDE_AUTH", nil)
}

func writeRawData(w http.ResponseWriter, data []byte, code int) {
	w.Header().Add("Content-Type", "application/octet-stream")
	w.WriteHeader(code)
	w.Write(data)
}

func nautichart(w http.ResponseWriter, r *http.Request) {
	// TODO: check POST request
	logrus.Error("NAUTICHART")

	ciphertext, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("error reading request bytes: %v", err), http.StatusBadRequest)
		return
	}

	plaintext, err := crypto.Decode(ciphertext, false, crypto.PUBLIC_NODE_AEAD)
	if err != nil {
		http.Error(w, fmt.Sprintf("error decoding request bytes: %v", err), http.StatusBadRequest)
		return
	}

	payload := string(plaintext)
	switch {
	case payload == NODE_OWNER_KEY:
		fallthrough
	case payload == PAYLOAD_KEY:
		token := &generated.WhirlpoolNauticalChart{
			AuthEndpoint: AUTH_ENDPOINT,
			SeasidePort:  int32(SEASIDE_PORT),
			ControlPort:  int32(CONTROL_PORT),
		}

		marshToken, err := proto.Marshal(token)
		if err != nil {
			http.Error(w, fmt.Sprintf("error marshalling token: %v", err), http.StatusBadRequest)
			return
		}

		tokenData, err := crypto.Encode(marshToken, nil, crypto.PUBLIC_NODE_AEAD)
		if err != nil {
			http.Error(w, fmt.Sprintf("error encrypting token: %v", err), http.StatusBadRequest)
			return
		}

		writeRawData(w, tokenData, http.StatusOK)
	default:
		http.Error(w, "wrong payload string", http.StatusBadRequest)
	}
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
		http.Error(w, fmt.Sprintf("error decoding request bytes: %v", err), http.StatusBadRequest)
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
		Token:      tokenData,
		UserZero:   int64(crypto.ZERO_USER_ID),
		Multiplier: int64(crypto.MULTIPLIER),
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
	logrus.Infoln("Node API setup, node owner key:", NODE_OWNER_KEY)

	http.HandleFunc(fmt.Sprintf("/%s", NAUTICHART_ENDPOINT), nautichart)
	// TODO: distribute stats: http.HandleFunc("/stats", stats)
	http.HandleFunc(fmt.Sprintf("/%s", AUTH_ENDPOINT), auth)
	// TODO: connect to network: http.HandleFunc("/connect", connect)

	network := fmt.Sprintf("%s:%d", INTERNAL_ADDRESS, port)
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
