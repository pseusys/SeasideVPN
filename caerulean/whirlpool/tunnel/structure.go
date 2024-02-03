package tunnel

import (
	"bytes"
	"fmt"
	"net"
	"sync"

	"github.com/songgao/water"
)

// Tunnel config object, represents tunnel interface and forwarding setup.
// Contains all the data necessary to setup and disable acket forwarding.
type TunnelConfig struct {
	// Mutex that will be enabled during all interface manipulations.
	mutex sync.Mutex

	// Tunnel interface for VPN packet forwarding, unix TUN device.
	Tunnel *water.Interface

	// Tunnel interface IP address.
	IP net.IP

	// Tunnel network properties: network address and CIDR.
	Network *net.IPNet

	// Buffer for storing iptables saved configuration.
	buffer bytes.Buffer
}

// Preserve current iptables configuration in a TunnelConfig object.
// Create and return the tunnel config pointer.
func Preserve() *TunnelConfig {
	conf := TunnelConfig{}
	conf.mutex.Lock()
	conf.storeForwarding()
	conf.mutex.Unlock()
	return &conf
}

// Open tunnel interface and setup iptables forwarding rules.
// Should be applied for TunnelConf object, initializes some of its fields.
// Accept tunnel, internal and external interface IP addresses, seaside, network and control ports as ints.
// Returns nil if everything is setup successfully, error otherwise.
func (conf *TunnelConfig) Open(tunIP, intIP, extIP string, seaPort, netPort, ctrlPort int) (err error) {
	conf.mutex.Lock()

	// Parse and initialize tunnel IP and network fields
	conf.IP, conf.Network, err = net.ParseCIDR(tunIP)
	if err != nil {
		return fmt.Errorf("error parsing tunnel network address (%s): %v", tunIP, err)
	}

	// Create and open TUN device
	conf.Tunnel, err = water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return fmt.Errorf("error allocating TUN interface: %v", err)
	}

	// Open tunnel interface
	err = conf.openInterface(extIP)
	if err != nil {
		return fmt.Errorf("error creating tunnel interface: %v", err)
	}

	// Setup iptables forwarding rules
	err = conf.openForwarding(intIP, extIP, seaPort, netPort, ctrlPort)
	if err != nil {
		return fmt.Errorf("error creating firewall rules: %v", err)
	}

	// Return no error
	conf.mutex.Unlock()
	return nil
}

// Close tunnel forwarding, restore saved iptables rules.
// Should be applied for TunnelConf object for tunnel and iptables configuration restoration.
func (conf *TunnelConfig) Close() {
	conf.mutex.Lock()
	conf.closeForwarding()
	conf.closeInterface()
	conf.Tunnel.Close()
	conf.mutex.Unlock()
}
