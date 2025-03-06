package users

import (
	"time"
)

type ProtocolType int

const (
	PROTOCOL_PORT    = 1
	PROTOCOL_TYPHOON = 2
)

// Viridian structure.
// Contains all the required information about connected viridian.
type Viridian struct {
	name string

	device string

	// Unique user identifier as a string.
	identifier string

	// Flag, whether user is privileged.
	admin bool

	// Peer ID of the viridian.
	peerID uint16

	// The protocol user is connected with.
	protocol ProtocolType

	// Resetting timer, updated on every healthcheck, removes user after timeout.
	reset *time.Timer
}

// Stop viridian connection and remove deletion timer.
// Should be applied for Viridian object.
func (viridian *Viridian) stop() {
	if viridian.reset != nil {
		viridian.reset.Stop()
	}
}
