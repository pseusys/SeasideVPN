package users

import (
	"fmt"
	"main/generated"
	"main/utils"
	"math"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	DEFAULT_MAX_VIRIDIANS = 10
	DEFAULT_MAX_ADMINS    = 5
)

// Viridian dictionary wrapper structure.
// Consists of the dictionary itself and limits that should be applied to users.
type ViridianDict struct {
	// Maximum number of viridians (not admins).
	maxViridians uint16

	// Maximum number of privileged viridian (admin).
	maxOverhead uint16

	// The viridian dictionary itself.
	entries map[uint16]*Viridian

	// The viridian dictionary re-mapped by unique IDs.
	uniques map[string]*Viridian

	// Mutex for viridian operations.
	mutex sync.Mutex
}

// Create viridian dictionary.
// Will use limits from environment variables and TunnelConfig from context.
// Accept context, return viridian dictionary pointer.
func NewViridianDict() (*ViridianDict, error) {
	// Retrieve limits from environment variables
	maxViridians := uint16(utils.GetIntEnv("SEASIDE_MAX_VIRIDIANS", DEFAULT_MAX_VIRIDIANS, 16))
	maxAdmins := uint16(utils.GetIntEnv("SEASIDE_MAX_ADMINS", DEFAULT_MAX_ADMINS, 16))
	maxTotal := maxViridians + maxAdmins

	// Exit if limit configuration is inconsistant
	if maxTotal > math.MaxUint16-3 {
		return nil, fmt.Errorf("error initializing viridian array: too many users requested: %d", maxTotal)
	}

	// Create viridian dictionary object and start sending packets to them
	dict := ViridianDict{
		maxViridians: maxViridians,
		maxOverhead:  maxAdmins,
		entries:      make(map[uint16]*Viridian, maxTotal),
		uniques:      make(map[string]*Viridian, maxTotal),
	}

	// Return dictionary pointer
	return &dict, nil
}

func (dict *ViridianDict) MaxConnected() uint16 {
	return dict.maxViridians + dict.maxOverhead
}

// Add a viridian to the dictionary.
// Check if there are available slots in the dictionary, parse token and other parameters.
// Create viridian, open VPN connection for it and add the viridian to the dictionary.
// Should be applied for ViridianDict object.
// Accept context, token, viridian address, gateway and port.
// Return viridian number and nil if added successfully and nil and error otherwise.
func (dict *ViridianDict) Add(viridianID uint16, viridianDevice *string, token *generated.UserToken, protocol ProtocolType) error {
	dict.mutex.Lock()
	defer dict.mutex.Unlock()

	// Check if there are slots available
	if !token.IsAdmin && len(dict.entries) >= int(dict.maxViridians) {
		return fmt.Errorf("can not connect any more viridians, connected: %d", len(dict.entries))
	} else if len(dict.entries) == int(dict.maxViridians+dict.maxOverhead) {
		return fmt.Errorf("can not connect any more admins, connected: %d", len(dict.entries))
	}

	viridian, ok := dict.uniques[token.Identifier]
	if ok {
		viridian.stop()
		delete(dict.entries, viridian.peerID)
	}

	// If found, setup deletion timer and create viridian object
	var deletionTimer *time.Timer
	if !token.IsAdmin {
		now := time.Now()
		timeout := token.Subscription.AsTime()
		if timeout.Before(now) {
			return fmt.Errorf("viridian timeout already expired (%d < %d)", timeout.Unix(), now.Unix())
		} else {
			deletionTimer = time.AfterFunc(timeout.Sub(now), func() { dict.Delete(viridianID, true) })
		}
	} else {
		deletionTimer = nil
	}

	// Create viridian object
	viridian = &Viridian{
		Name:       token.Name,
		Device:     *viridianDevice,
		Identifier: token.Identifier,
		admin:      token.IsAdmin,
		peerID:     viridianID,
		protocol:   protocol,
		reset:      deletionTimer,
	}

	dict.entries[viridianID] = viridian
	dict.uniques[token.Identifier] = viridian
	return nil
}

// Get viridian from the dictionary by ID.
// Should be applied for ViridianDict object.
// Accept viridian ID.
// Return viridian pointer and True if successful, nil and False otherwise.
func (dict *ViridianDict) Get(userID uint16, protocol ProtocolType) (*Viridian, bool) {
	value, ok := dict.entries[userID]
	ok = ok && value.protocol == protocol
	return value, ok
}

// Remove viridian from viridian list.
// Viridian pointer is replaced by nil.
// Should be applied for ViridianDict object.
// Accept viridian ID (unsigned 16-bit integer) and flag if viridian was deleted by timeout.
func (dict *ViridianDict) Delete(viridianID uint16, timeout bool) {
	dict.mutex.Lock()
	defer dict.mutex.Unlock()

	// Retrieve viridian from the dictionary
	viridian, ok := dict.entries[viridianID]
	if !ok {
		return
	}

	// Stop viridian and remove it from the dictionary
	viridian.stop()
	delete(dict.entries, viridianID)

	// Log appropriate message if deleted by timeout
	if timeout {
		logrus.Infof("User %d deleted because their subscription has expired!", viridianID)
	} else {
		logrus.Infof("User %d deleted successfully", viridianID)
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
