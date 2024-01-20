package users

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"main/crypto"
	"main/generated"
	"main/utils"
	"math"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

type Viridian struct {
	UID     string
	AEAD    cipher.AEAD
	reset   *time.Timer
	admin   bool
	timeout time.Time
	Address net.IP
	Gateway net.IP
	Port    uint32
}

const (
	USER_WAITING_OVERTIME   = 5
	FIRST_HEALTHCHECK_DELAY = time.Minute * time.Duration(USER_WAITING_OVERTIME)
)

var (
	VIRIDIANS  []*Viridian
	ITERATOR   uint16
	MAX_USERS  uint16
	MAX_ADMINS uint16
	MAX_TOTAL  uint16
)

func init() {
	ITERATOR = 0
	MAX_USERS = uint16(utils.GetIntEnv("SEASIDE_MAX_USERS"))
	MAX_ADMINS = uint16(utils.GetIntEnv("SEASIDE_MAX_ADMINS"))
	MAX_TOTAL = MAX_USERS + MAX_ADMINS

	if MAX_TOTAL > math.MaxUint16-3 {
		logrus.Fatalf("Error initializing viridian array: too many users requested: %d", MAX_TOTAL)
	}
	VIRIDIANS = make([]*Viridian, MAX_TOTAL)
}

func isViridianOvertime(viridian *Viridian) bool {
	return !viridian.admin && viridian.timeout.Before(time.Now().UTC())
}

func AddViridian(token *generated.UserToken, address, gateway net.IP, port uint32) (*uint16, generated.ControlResponseStatus, error) {
	aead, err := crypto.ParseCipher(token.Session)
	if err != nil {
		return nil, generated.ControlResponseStatus_ERROR, fmt.Errorf("error parsing encryption algorithm for user: %v", err)
	}

	var limit uint16
	if token.Privileged {
		limit = MAX_TOTAL
	} else {
		limit = MAX_USERS
	}
	initial := ITERATOR % limit
	ITERATOR = initial

	for VIRIDIANS[ITERATOR] != nil {
		ITERATOR = (ITERATOR + 1) % limit
		if ITERATOR == initial {
			break
		}
	}
	if VIRIDIANS[ITERATOR] != nil {
		return nil, generated.ControlResponseStatus_OVERLOAD, errors.New("error searching place for a new user")
	}

	userID := ITERATOR + 2
	deletionTimer := time.AfterFunc(FIRST_HEALTHCHECK_DELAY, func() { DeleteViridian(userID, true) })
	viridian := &Viridian{token.Uid, aead, deletionTimer, token.Privileged, token.Subscription.AsTime(), address, gateway, port}

	if isViridianOvertime(viridian) {
		return nil, generated.ControlResponseStatus_OVERTIME, errors.New("viridian subscription outdated")
	} else {
		VIRIDIANS[ITERATOR] = viridian
		logrus.Infof("User %d (uid: %s, privileged: %t) created", userID, token.Uid, token.Privileged)
		return &userID, generated.ControlResponseStatus_SUCCESS, nil
	}
}

func GetViridian(userID uint16) *Viridian {
	return VIRIDIANS[userID-2]
}

func DeleteViridian(userID uint16, timeout bool) {
	VIRIDIANS[userID-2] = nil
	if timeout {
		logrus.Infof("User %d deleted by unhealthy timeout", userID)
	} else {
		logrus.Infof("User %d deleted successfully", userID)
	}
}

func UpdateViridian(userID uint16, nextIn int32) (generated.ControlResponseStatus, error) {
	viridian := VIRIDIANS[userID-2]
	if viridian != nil {
		if isViridianOvertime(viridian) {
			DeleteViridian(userID, false)
			return generated.ControlResponseStatus_OVERTIME, errors.New("viridian subscription outdated")
		} else {
			viridian.reset.Reset(time.Duration(nextIn*USER_WAITING_OVERTIME) * time.Second)
			return generated.ControlResponseStatus_HEALTHPONG, nil
		}
	} else {
		return generated.ControlResponseStatus_ERROR, errors.New("requested viridian doesn't exist")
	}
}
