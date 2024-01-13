package users

import (
	"crypto/cipher"
	"errors"
	"main/crypto"
	"main/generated"
	"main/utils"
	"math"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

type Viridian struct {
	Aead    cipher.AEAD
	reset   *time.Timer
	Address net.IP
	Gateway net.IP
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

func InitializeViridians(maxUsers uint16, maxAdmins uint16) {
	ITERATOR = 0
	MAX_USERS = maxUsers
	MAX_ADMINS = maxAdmins
	MAX_TOTAL = maxUsers + maxAdmins

	if MAX_TOTAL > math.MaxUint16-3 {
		logrus.Fatalf("error initializing viridian array: too many users requested %d", MAX_TOTAL)
	}
	VIRIDIANS = make([]*Viridian, MAX_TOTAL)
}

func AddViridian(token *generated.UserToken, address net.IP, gateway net.IP) (*uint16, generated.UserControlResponseStatus, error) {
	aead, err := crypto.ParseSymmetricalAlgorithm(token.Session)
	if err != nil {
		return nil, generated.UserControlResponseStatus_ERROR, utils.JoinError("error parsing encryption algorithm for user", err)
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
		return nil, generated.UserControlResponseStatus_OVERLOAD, errors.New("error searching place for a new user")
	}

	userID := ITERATOR + 2
	deletionTimer := time.AfterFunc(FIRST_HEALTHCHECK_DELAY, func() { DeleteViridian(userID, true) })
	VIRIDIANS[ITERATOR] = &Viridian{aead, deletionTimer, address, gateway}
	logrus.Infof("User %d (uid: %s, privileged: %t) created", userID, token.Uid, token.Privileged)
	return &userID, generated.UserControlResponseStatus_SUCCESS, nil
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

func UpdateViridian(userID uint16, nextIn int32) (generated.UserControlResponseStatus, error) {
	viridian := VIRIDIANS[userID-2]
	if viridian != nil {
		viridian.reset.Reset(time.Duration(nextIn*USER_WAITING_OVERTIME) * time.Second)
		return generated.UserControlResponseStatus_HEALTHPONG, nil
	} else {
		return generated.UserControlResponseStatus_ERROR, errors.New("requested viridian doesn't exist")
	}
}
