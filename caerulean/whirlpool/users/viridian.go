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

// Viridian structure.
// Contains all the required information about connected viridian.
type Viridian struct {
	// Unique user identifier as a string.
	UID string

	// User session cipher AEAD, encrypts all incoming VPN packets.
	AEAD cipher.AEAD

	// Resetting timer, updated on every healthcheck, removes user after timeout.
	reset *time.Timer

	// Flag, whether user is privileged.
	admin bool

	// User subscription expiration timeout, non-privileged user is deleted after the timeout.
	timeout *time.Time

	// User internal IP address: encrypted packet "dst" address will be set to this IP.
	Address net.IP

	// User gateway IP address: outer packet "dst" address will be set to this IP.
	Gateway net.IP

	// User port number, integer.
	Port uint32
}

const (
	// How much time the node waits for the first healthping message from user (this number times 3 seconds).
	// Also, the node will wait NextIn * this number of seconds for every subsequent healthping message.
	USER_WAITING_OVERTIME = 5

	// Time in seconds to wait for the first healthping message from user (this number times 3 seconds).
	FIRST_HEALTHCHECK_DELAY = time.Second * time.Duration(USER_WAITING_OVERTIME*3)
)

var (
	// Viridians array contains array of pointers.
	VIRIDIANS []*Viridian

	// Viridian array iterator (16-bit unsigned integer).
	ITERATOR uint16

	// Maximum amount of non-privileged viridians supported by the node.
	MAX_USERS uint16

	// Maximum amount of privileged viridians supported by the node.
	MAX_ADMINS uint16

	// Maximum total amount of viridians supported by the node.
	MAX_TOTAL uint16
)

// Initialize package variables from environment variables.
// Throw an error if the node supports too many viridians (maximum total amount is 65532).
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

// Helper function, determine whether viridian should be removed.
// Viridian is removed if it is NOT privileged AND if viridian subscription has expired.
// Accept viridian pointer, return flag if the viridian should be deleted.
func isViridianOvertime(viridian *Viridian) bool {
	return !viridian.admin && viridian.timeout != nil && viridian.timeout.Before(time.Now().UTC())
}

// Add new viridian to the viridian array.
// Viridian pointer is inserted into array, user ID is its' position in this array.
// Empty places in the array are nil. New viridians are inserted according to "Next Fit" policy.
// Accept user token pointer, user address and gateway IP addresses and port number.
// Return user ID pointer, control response success status and nil if user is added successfully, otherwise nil, error status and error.
func AddViridian(token *generated.UserToken, address, gateway net.IP, port uint32) (*uint16, generated.ControlResponseStatus, error) {
	// Create viridian session cipher
	aead, err := crypto.ParseCipher(token.Session)
	if err != nil {
		return nil, generated.ControlResponseStatus_ERROR, fmt.Errorf("error parsing encryption algorithm for user: %v", err)
	}

	// Find viridian array empty position searching limit
	var limit uint16
	if token.Privileged {
		limit = MAX_TOTAL
	} else {
		limit = MAX_USERS
	}
	initial := ITERATOR % limit
	ITERATOR = initial

	// Iterate viridian arry, search for empty place
	for VIRIDIANS[ITERATOR] != nil {
		ITERATOR = (ITERATOR + 1) % limit
		if ITERATOR == initial {
			break
		}
	}

	// If not found, return an error
	if VIRIDIANS[ITERATOR] != nil {
		return nil, generated.ControlResponseStatus_OVERLOAD, errors.New("error searching place for a new user")
	}

	// If found, setup deletion timer and create viridian object
	userID := ITERATOR + 2
	subscriptionTimeout := token.Subscription.AsTime()
	deletionTimer := time.AfterFunc(FIRST_HEALTHCHECK_DELAY, func() { DeleteViridian(userID, true) })
	viridian := &Viridian{token.Uid, aead, deletionTimer, token.Privileged, &subscriptionTimeout, address, gateway, port}

	// If viridian subscription is expired, throw error, otherwise insert the viridian and return its' ID
	if isViridianOvertime(viridian) {
		return nil, generated.ControlResponseStatus_OVERTIME, errors.New("viridian subscription outdated")
	} else {
		VIRIDIANS[ITERATOR] = viridian
		logrus.Infof("User %d (uid: %s, privileged: %t) created", userID, token.Uid, token.Privileged)
		return &userID, generated.ControlResponseStatus_SUCCESS, nil
	}
}

// Get viridian object from viridian list.
// Accept viridan ID (unsigned 16-bit integer). Return viridian pointer.
func GetViridian(userID uint16) *Viridian {
	return VIRIDIANS[userID-2]
}

// Remove viridian from viridian list.
// Viridian pointer is replaced by nil.
// Accept viridian ID (unsigned 16-bit integer) and flag if viridian was deleted by timeout.
func DeleteViridian(userID uint16, timeout bool) {
	VIRIDIANS[userID-2] = nil
	if timeout {
		logrus.Infof("User %d deleted by unhealthy timeout", userID)
	} else {
		logrus.Infof("User %d deleted successfully", userID)
	}
}

// Update viridian, replace its' deletion timer with NextIn number.
// Should be called upon healthping control message receiving.
// Accept user ID (unsigned 16-bit integer) and NextIn number (number of seconds that will elapse before the next healthping).
// Return control response success status and nil if viridian is updated successfully, otherwise error status and error.
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
