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

type ViridianDict struct {
	viridianWaitingOvertime uint
	firstHealthcheckDelay   time.Duration

	maxViridians uint
	maxOverhead  uint
	entries      map[uint16]*Viridian

	mutex sync.Mutex
}

func NewViridianDict(ctx context.Context) *ViridianDict {
	maxViridians := uint16(utils.GetIntEnv("SEASIDE_MAX_VIRIDIANS"))
	maxAdmins := uint16(utils.GetIntEnv("SEASIDE_MAX_ADMINS"))
	maxTotal := maxViridians + maxAdmins

	if maxTotal > math.MaxUint16-3 {
		logrus.Fatalf("Error initializing viridian array: too many users requested: %d", maxTotal)
	}

	viridianWaitingOvertime := uint(utils.GetIntEnv("SEASIDE_VIRIDIAN_WAITING_OVERTIME"))
	firstHealthcheckDelayMultiplier := uint(utils.GetIntEnv("SEASIDE_VIRIDIAN_FIRST_HEALTHCHECK_DELAY"))
	firstHealthcheckDelay := time.Second * time.Duration(viridianWaitingOvertime*firstHealthcheckDelayMultiplier)

	tunnelConfig, ok := tunnel.FromContext(ctx)
	if !ok {
		logrus.Fatalf("tunnel config not found in context: %v", ctx)
	}

	dict := ViridianDict{
		viridianWaitingOvertime: viridianWaitingOvertime,
		firstHealthcheckDelay:   firstHealthcheckDelay,
		maxViridians:            uint(maxViridians),
		maxOverhead:             uint(maxAdmins),
		entries:                 make(map[uint16]*Viridian, maxTotal),
	}
	go dict.SendPacketsToViridians(ctx, tunnelConfig.Tunnel, tunnelConfig.Network)

	return &dict
}

func (dict *ViridianDict) Add(ctx context.Context, token *generated.UserToken, address, gateway net.IP, port uint16) (*uint16, error) {
	dict.mutex.Lock()

	if !token.Privileged && len(dict.entries) >= int(dict.maxViridians) {
		dict.mutex.Unlock()
		return nil, status.Error(codes.ResourceExhausted, "can not connect any more viridians")
	} else if len(dict.entries) == int(dict.maxViridians+dict.maxOverhead) {
		dict.mutex.Unlock()
		return nil, status.Error(codes.ResourceExhausted, "can not connect any more admins")
	}

	// Create viridian session cipher
	aead, err := crypto.ParseCipher(token.Session)
	if err != nil {
		dict.mutex.Unlock()
		return nil, status.Errorf(codes.InvalidArgument, "error parsing encryption algorithm for user: %v", err)
	}

	internalAddress := utils.GetEnv("SEASIDE_ADDRESS")

	// Resolve UDP address
	localAddress, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:0", internalAddress))
	if err != nil {
		dict.mutex.Unlock()
		return nil, status.Errorf(codes.Internal, "error resolving local address: %v", err)
	}

	// Create connection
	seaConn, err := net.ListenUDP("udp4", localAddress)
	if err != nil {
		dict.mutex.Unlock()
		return nil, status.Errorf(codes.Internal, "Error resolving connection (%s): %v", localAddress.String(), err)
	}

	_, userID, err := utils.GetIPAndPortFromAddress(seaConn.LocalAddr())
	if err != nil {
		dict.mutex.Unlock()
		return nil, status.Errorf(codes.Internal, "error resolving user sea port: %v", err)
	}

	if utils.IsSpecialIPAddress(userID) {
		dict.mutex.Unlock()
		return nil, status.Errorf(codes.Internal, "error opening UDP listener, port: %d", userID)
	}

	seaCtx, cancel := context.WithCancel(ctx)

	// If found, setup deletion timer and create viridian object
	subscriptionTimeout := token.Subscription.AsTime()
	deletionTimer := time.AfterFunc(time.Duration(dict.firstHealthcheckDelay), func() { dict.Delete(userID, true) })

	logrus.Infof("Viridian with UID: %s, admin: %t, address: %v, gateway: %v, port: %d received...", token.Uid, token.Privileged, address, gateway, port)
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
		dict.mutex.Unlock()
		return nil, status.Error(codes.DeadlineExceeded, "viridian subscription outdated")
	}

	tunnelConfig, ok := tunnel.FromContext(ctx)
	if !ok {
		dict.mutex.Unlock()
		return nil, status.Error(codes.Internal, "tunnel config not found in context")
	}

	dict.entries[userID] = viridian
	go dict.ReceivePacketsFromViridian(seaCtx, userID, seaConn, tunnelConfig.Tunnel, tunnelConfig.Network)

	dict.mutex.Unlock()
	return &userID, nil
}

func (dict *ViridianDict) Get(userID uint16) (*Viridian, bool) {
	value, ok := dict.entries[userID]
	return value, ok
}

// Update viridian, replace its' deletion timer with NextIn number.
// Should be called upon healthping control message receiving.
// Accept user ID (unsigned 16-bit integer) and NextIn number (number of seconds that will elapse before the next healthping).
// Return control response success status and nil if viridian is updated successfully, otherwise error status and error.
func (dict *ViridianDict) Update(userID uint16, nextIn int32) error {
	dict.mutex.Lock()

	viridian, ok := dict.entries[userID]
	if !ok {
		dict.mutex.Unlock()
		return status.Errorf(codes.InvalidArgument, "requested viridian %d doesn't exist", userID)
	}

	if viridian.isViridianOvertime() {
		dict.Delete(userID, false)
		dict.mutex.Unlock()
		return status.Errorf(codes.DeadlineExceeded, "viridian %d subscription outdated", userID)
	} else {
		viridian.reset.Reset(time.Duration(nextIn*int32(dict.viridianWaitingOvertime)) * time.Second)
		dict.mutex.Unlock()
		return nil
	}
}

// Remove viridian from viridian list.
// Viridian pointer is replaced by nil.
// Accept viridian ID (unsigned 16-bit integer) and flag if viridian was deleted by timeout.
func (dict *ViridianDict) Delete(userID uint16, timeout bool) {
	dict.mutex.Lock()

	viridian, ok := dict.entries[userID]
	if !ok {
		dict.mutex.Unlock()
		return
	}

	viridian.stop()
	delete(dict.entries, userID)

	if timeout {
		logrus.Infof("User %d deleted by unhealthy timeout", userID)
	} else {
		logrus.Infof("User %d deleted successfully", userID)
	}
	dict.mutex.Unlock()
}

func (dict *ViridianDict) Clear() {
	dict.mutex.Lock()
	for key, viridian := range dict.entries {
		viridian.stop()
		delete(dict.entries, key)
	}
	dict.mutex.Unlock()
}
