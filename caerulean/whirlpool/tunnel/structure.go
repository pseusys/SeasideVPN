package tunnel

import (
	"bytes"
	"fmt"
	"main/utils"
	"net"
	"sync"

	"github.com/songgao/water"
)

// Tunnel IP address, also serves as gateway address for tunnel network interface.
// Last bits of the packet source network address are used to store state user information in "iptables" firewall.
// Last 2 bytes of will be used for attributing packages belonging to different viridians.
const TUNNEL_IP = "172.16.0.1/12"

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

	// Limit rules for VPN data transfer.
	vpnDataKbyteLimitRule []string

	// Limit rules for control (TCP, gRPC) data transfer.
	controlPacketLimitRule []string

	// Limit rules for ICPM (Ping) data transfer.
	icmpPacketPACKETLimitRules []string

	// Tunnel MTU.
	mtu int
}

// Preserve current iptables configuration in a TunnelConfig object.
// Create and return the tunnel config pointer.
func Preserve() *TunnelConfig {
	maxViridians := utils.GetIntEnv("SEASIDE_MAX_VIRIDIANS") + utils.GetIntEnv("SEASIDE_MAX_ADMINS")
	burstMultiplier := utils.GetIntEnv("SEASIDE_BURST_LIMIT_MULTIPLIER")

	vpnDataKbyteLimitRule := readLimit("SEASIDE_VPN_DATA_LIMIT", "%dkb/s", maxViridians, burstMultiplier)
	controlPacketLimitRule := readLimit("SEASIDE_CONTROL_PACKET_LIMIT", "%d/sec", maxViridians, burstMultiplier)
	icmpPacketPACKETLimitRules := readLimit("SEASIDE_ICMP_PACKET_LIMIT", "%d/sec", maxViridians, burstMultiplier)
	mtu := utils.GetIntEnv("SEASIDE_TUNNEL_MTU")

	conf := TunnelConfig{
		vpnDataKbyteLimitRule:      vpnDataKbyteLimitRule,
		controlPacketLimitRule:     controlPacketLimitRule,
		icmpPacketPACKETLimitRules: icmpPacketPACKETLimitRules,
		mtu:                        mtu,
	}

	conf.mutex.Lock()
	conf.storeForwarding()
	conf.mutex.Unlock()

	return &conf
}

// Open tunnel interface and setup iptables forwarding rules.
// Should be applied for TunnelConf object, initializes some of its fields.
// Accept tunnel, internal and external interface IP addresses, seaside, network and control ports as ints.
// Returns nil if everything is setup successfully, error otherwise.
func (conf *TunnelConfig) Open() (err error) {
	conf.mutex.Lock()
	defer conf.mutex.Unlock()

	// Parse IPs and control port number from environment variables
	intIP := utils.GetEnv("SEASIDE_ADDRESS")
	extIP := utils.GetEnv("SEASIDE_EXTERNAL")
	ctrlPort := utils.GetIntEnv("SEASIDE_CTRLPORT")

	// Parse and initialize tunnel IP and network fields
	conf.IP, conf.Network, err = net.ParseCIDR(TUNNEL_IP)
	if err != nil {
		return fmt.Errorf("error parsing tunnel network address (%s): %v", TUNNEL_IP, err)
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
	err = conf.openForwarding(intIP, extIP, ctrlPort)
	if err != nil {
		return fmt.Errorf("error creating firewall rules: %v", err)
	}

	// Return no error
	return nil
}

// Close tunnel forwarding, restore saved iptables rules.
// Should be applied for TunnelConf object for tunnel and iptables configuration restoration.
func (conf *TunnelConfig) Close() {
	conf.mutex.Lock()
	defer conf.mutex.Unlock()

	conf.closeForwarding()
	conf.closeInterface()
	conf.Tunnel.Close()
}
