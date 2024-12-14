package users

import (
	"context"
	"fmt"
	"main/crypto"
	"main/generated"
	"main/tunnel"
	"main/utils"
	"math"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Viridian dictionary wrapper structure.
// Consists of the dictionary itself and limits that should be applied to users.
type ViridianDict struct {
	// A multiplier for maximum healthcheck waiting time for viridian (before deletion).
	viridianWaitingOvertime uint16

	// Time before the first healthcheck message from viridian.
	firstHealthcheckDelay time.Duration

	// Maximum number of viridians (not admins).
	maxViridians uint16

	// Maximum number of privileged viridian (admin).
	maxOverhead uint16

	// The viridian dictionary itself.
	entries map[uint16]*Viridian

	// Mutex for viridian operations.
	mutex sync.Mutex
}

// Create viridian dictionary.
// Will use limits from environment variables and TunnelConfig from context.
// Accept context, return viridian dictionary pointer.
func NewViridianDict(ctx context.Context) *ViridianDict {
	// Retrieve limits from environment variables
	maxViridians := uint16(utils.GetIntEnv("SEASIDE_MAX_VIRIDIANS", 16))
	maxAdmins := uint16(utils.GetIntEnv("SEASIDE_MAX_ADMINS", 16))
	maxTotal := maxViridians + maxAdmins

	// Exit if limit configuration is inconsistant
	if maxTotal > math.MaxUint16-3 {
		logrus.Fatalf("Error initializing viridian array: too many users requested: %d", maxTotal)
	}

	// Retrieve time limits from environment variables
	viridianWaitingOvertime := uint16(utils.GetIntEnv("SEASIDE_WAITING_OVERTIME", 16))
	firstHealthcheckDelayMultiplier := uint16(utils.GetIntEnv("SEASIDE_FIRST_HEALTHCHECK_DELAY", 16))
	firstHealthcheckDelay := time.Second * time.Duration(viridianWaitingOvertime*firstHealthcheckDelayMultiplier)

	// Retrieve tunnel configurations from context
	tunnelConfig, ok := tunnel.FromContext(ctx)
	if !ok {
		logrus.Fatalf("tunnel config not found in context: %v", ctx)
	}

	// Create viridian dictionary object and start sending packets to them
	dict := ViridianDict{
		viridianWaitingOvertime: viridianWaitingOvertime,
		firstHealthcheckDelay:   firstHealthcheckDelay,
		maxViridians:            maxViridians,
		maxOverhead:             maxAdmins,
		entries:                 make(map[uint16]*Viridian, maxTotal),
	}
	go dict.SendPacketsToViridians(ctx, tunnelConfig.Tunnel, tunnelConfig.Network)

	// Return dictionary pointer
	return &dict
}

// Add a viridian to the dictionary.
// Check if there are available slots in the dictionary, parse token and other parameters.
// Create viridian, open VPN connection for it and add the viridian to the dictionary.
// Should be applied for ViridianDict object.
// Accept context, token, viridian address, gateway and port.
// Return viridian number and nil if added successfully and nil and error otherwise.
func (dict *ViridianDict) Add(ctx context.Context, token *generated.UserToken, address, gateway net.IP, port uint16) (*uint16, error) {
	dict.mutex.Lock()
	defer dict.mutex.Unlock()

	// Check if there are slots available
	if !token.Privileged && len(dict.entries) >= int(dict.maxViridians) {
		return nil, status.Error(codes.ResourceExhausted, "can not connect any more viridians")
	} else if len(dict.entries) == int(dict.maxViridians+dict.maxOverhead) {
		return nil, status.Error(codes.ResourceExhausted, "can not connect any more admins")
	}

	// Create viridian session cipher
	aead, err := crypto.ParseCipher(token.Session)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error parsing encryption algorithm for user: %v", err)
	}

	// Parse internal IP address from environment variable
	internalAddress := utils.GetEnv("SEASIDE_ADDRESS")

	// Resolve UDP address
	localAddress, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:0", internalAddress))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error resolving local address: %v", err)
	}

	// Create VPN connection
	seaConn, err := net.ListenUDP("udp4", localAddress)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error resolving connection (%s): %v", localAddress.String(), err)
	}

	// Get connection port number
	_, userID, err := utils.GetIPAndPortFromAddress(seaConn.LocalAddr())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error resolving user sea port: %v", err)
	}

	// Check if user number combined with tunnel IP create special IP address
	if utils.IsSpecialIPAddress(userID) {
		return nil, status.Errorf(codes.Internal, "error opening UDP listener, port: %d", userID)
	}

	// Derive child context from context
	seaCtx, cancel := context.WithCancel(ctx)

	// If found, setup deletion timer and create viridian object
	subscriptionTimeout := token.Subscription.AsTime()
	deletionTimer := time.AfterFunc(time.Duration(dict.firstHealthcheckDelay), func() { dict.Delete(userID, true) })

	// Create viridian object
	viridian := &Viridian{
		UID:           token.Uid,
		AEAD:          aead,
		reset:         deletionTimer,
		admin:         token.Privileged,
		timeout:       &subscriptionTimeout,
		Address:       address,
		Gateway:       gateway,
		Port:          port,
		CancelContext: cancel,
		SeaConn:       seaConn,
	}

	// If viridian subscription is expired, throw error, otherwise insert the viridian and return its' ID
	if viridian.isViridianOvertime() {
		return nil, status.Error(codes.DeadlineExceeded, "viridian subscription outdated")
	}

	// Retrieve tunnel config from context
	tunnelConfig, ok := tunnel.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "tunnel config not found in context")
	}

	// Launch goroutine for the created viridian
	dict.entries[userID] = viridian
	go dict.ReceivePacketsFromViridian(seaCtx, userID, seaConn, tunnelConfig.Tunnel, tunnelConfig.Network)

	// Return viridian ID and no error
	return &userID, nil
}

// Get viridian from the dictionary by ID.
// Should be applied for ViridianDict object.
// Accept viridian ID.
// Return viridian pointer and True if successful, nil and False otherwise.
func (dict *ViridianDict) Get(userID uint16) (*Viridian, bool) {
	value, ok := dict.entries[userID]
	return value, ok
}

// Update viridian, replace its' deletion timer with NextIn number.
// Should be called upon healthping control message receiving.
// Should be applied for ViridianDict object.
// Accept user ID (unsigned 16-bit integer) and NextIn number (number of seconds that will elapse before the next healthping).
// Return control response success status and nil if viridian is updated successfully, otherwise error status and error.
func (dict *ViridianDict) Update(userID uint16, nextIn int32) error {
	dict.mutex.Lock()
	defer dict.mutex.Unlock()

	// Retrieve viridian from the dictionary
	viridian, ok := dict.entries[userID]
	if !ok {
		return status.Errorf(codes.InvalidArgument, "requested viridian %d doesn't exist", userID)
	}

	// Update viridian if not overtime, throw error otherwise
	if viridian.isViridianOvertime() {
		dict.Delete(userID, false)
		return status.Errorf(codes.DeadlineExceeded, "viridian %d subscription outdated", userID)
	} else {
		viridian.reset.Reset(time.Duration(nextIn+int32(dict.viridianWaitingOvertime)) * time.Second)
		return nil
	}
}

// Remove viridian from viridian list.
// Viridian pointer is replaced by nil.
// Should be applied for ViridianDict object.
// Accept viridian ID (unsigned 16-bit integer) and flag if viridian was deleted by timeout.
func (dict *ViridianDict) Delete(userID uint16, timeout bool) {
	dict.mutex.Lock()
	defer dict.mutex.Unlock()

	// Retrieve viridian from the dictionary
	viridian, ok := dict.entries[userID]
	if !ok {
		return
	}

	// Stop viridian and remove it from the dictionary
	viridian.stop()
	delete(dict.entries, userID)

	// Log appropriate message if deleted by timeout
	if timeout {
		logrus.Infof("User %d deleted by unhealthy timeout", userID)
	} else {
		logrus.Infof("User %d deleted successfully", userID)
	}
}

// Clear viridan dictionary.
// Stop all viridian connections and delete all the objects.
// Should be applied for ViridianDict object.
func (dict *ViridianDict) Clear() {
	dict.mutex.Lock()
	defer dict.mutex.Unlock()
	for key, viridian := range dict.entries {
		viridian.stop()
		delete(dict.entries, key)
	}
}
