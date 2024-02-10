package main

import (
	"context"
	"errors"
	"fmt"
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
	// Node owner XChaCha20-Poly1305 key (is known to node admins only).
	NODE_OWNER_KEY string

	// Viridian XChaCha20-Poly1305 node key (is known to all seaside network users).
	PAYLOAD_KEY string

	// Authentication endpoint name.
	AUTH_ENDPOINT string
)

// Initialize package variables from environment variables.
func init() {
	NODE_OWNER_KEY = utils.GetEnv("SEASIDE_PAYLOAD_OWNER")
	PAYLOAD_KEY = utils.GetEnv("SEASIDE_PAYLOAD_USER")

	AUTH_ENDPOINT = utils.GetEnv("SEASIDE_AUTH")
}

// Authentication HTTP endpoint.
func auth(w http.ResponseWriter, r *http.Request) {
	// Check HTTP method - should be POST
	if r.Method != "POST" {
		writeHttpError(w, fmt.Errorf("method %s not supported", r.Method), http.StatusBadRequest)
		return
	}

	// Read and parse request message
	message := &generated.UserDataForWhirlpool{}
	err := readHttpRequest(r, message)
	if err != nil {
		writeHttpError(w, fmt.Errorf("error decrypting HTTP request: %v", err), http.StatusBadRequest)
		return
	}

	// Check node owner key
	if message.OwnerKey != NODE_OWNER_KEY {
		writeHttpError(w, errors.New("wrong owner key"), http.StatusBadRequest)
		return
	}

	// Create and marshall user token
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

	// Encode token
	tokenData, err := crypto.Encode(marshToken, crypto.PRIVATE_NODE_AEAD)
	if err != nil {
		writeHttpError(w, fmt.Errorf("error encrypting token: %v", err), http.StatusBadRequest)
		return
	}

	// Create and marshall response
	response := &generated.UserCertificate{
		Token:       tokenData,
		UserZero:    int32(crypto.ZERO_USER_ID),
		SeasidePort: int32(SEASIDE_PORT),
		ControlPort: int32(CONTROL_PORT),
	}

	// Send response
	writeHttpData(w, response)
}

// Initialize node network HTTP API.
// Accepts Context for graceful termination, internal network address (as a string) and TCP/HTTP port number for network endpoints hosting.
// NB! this method is blocking, so it should be run as goroutine.
func InitNetAPI(ctx context.Context, internalAddress string, port int) {
	logrus.Infof("Node API setup, node owner key: %v", NODE_OWNER_KEY)

	// Create server
	network := fmt.Sprintf("%s:%d", internalAddress, port)
	logrus.Debugf("Listening for HTTP requests at: %s", network)
	server := &http.Server{Addr: network, BaseContext: func(net.Listener) context.Context { return ctx }}

	// Assign endpoints
	// TODO: distribute stats: http.HandleFunc("/stats", stats)
	http.HandleFunc(fmt.Sprintf("/%s", AUTH_ENDPOINT), auth)
	// TODO: connect to network: http.HandleFunc("/connect", connect)

	// Listen and serve
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Error serving HTTP server: %v", err)
	}
}

// Initialize node private key.
func ExchangeNodeKey() {
	var err error
	crypto.PRIVATE_NODE_AEAD, crypto.PRIVATE_NODE_KEY, err = crypto.GenerateCipher()
	if err != nil {
		logrus.Fatalf("Error private node cipher generating: %v", err)
	}

	// TODO: send public and private keys to surface
}
