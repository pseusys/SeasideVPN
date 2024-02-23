package users

import (
	"context"
	"crypto/cipher"
	"net"
	"time"
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
	Port uint16

	CancelContext context.CancelFunc

	SeaConn *net.UDPConn
}

// Helper function, determine whether viridian should be removed.
// Viridian is removed if it is NOT privileged AND if viridian subscription has expired.
// Accept viridian pointer, return flag if the viridian should be deleted.
func (viridian *Viridian) isViridianOvertime() bool {
	return !viridian.admin && viridian.timeout != nil && viridian.timeout.Before(time.Now().UTC())
}

func (viridian *Viridian) stop() {
	viridian.reset.Stop()
	viridian.CancelContext()
	viridian.SeaConn.Close()
}
