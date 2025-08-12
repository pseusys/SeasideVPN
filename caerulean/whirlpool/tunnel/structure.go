package tunnel

import (
	"fmt"
	"main/utils"
	"net"
	"sync"

	"github.com/google/nftables"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

// Tunnel IP address, also serves as gateway address for tunnel network interface.
// Last bits of the packet source network address are used to store state user information in "iptables" firewall.
// Last 2 bytes of will be used for attributing packages belonging to different viridians.
const (
	DEFAULT_TUNNEL_NETWORK = "172.16.0.1/12"
	DEFAULT_TUNNEL_NAME    = "seatun"
	DEFAULT_TUNNEL_MTU     = 1500

	DEFAULT_BURST_MULTIPLIER = 3

	DEFAULT_API_PORT     = 8587
	DEFAULT_PORT_PORT    = 29384
	DEFAULT_TYPHOON_PORT = 29384

	REQUIRED_TUNNEL_NETWORK_BITS = 16
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

	// Default network properties: network address and CIDR.
	Default *net.IPNet

	// Buffer for storing iptables saved configuration.
	Nftable *nftables.Table

	// Tunnel MTU.
	mtu int32

	// Tunnel name.
	name string
}

// Preserve current iptables configuration in a TunnelConfig object.
// Create and return the tunnel config pointer.
func Preserve() (*TunnelConfig, error) {
	defaultNet, err := findDefaultInterface()
	if err != nil {
		return nil, fmt.Errorf("error finding default IP address: %v", err)
	}
	mtu := int32(utils.GetIntEnv("SEASIDE_TUNNEL_MTU", DEFAULT_TUNNEL_MTU, 32))
	name := utils.GetEnv("SEASIDE_TUNNEL_NAME", DEFAULT_TUNNEL_NAME)

	conf := TunnelConfig{
		Default: defaultNet,
		mtu:     mtu,
		name:    name,
	}

	return &conf, nil
}

// Open tunnel interface and setup iptables forwarding rules.
// Should be applied for TunnelConf object, initializes some of its fields.
// Accept tunnel, internal and external interface IP addresses, seaside, network and control ports as ints.
// Returns nil if everything is setup successfully, error otherwise.
func (conf *TunnelConfig) Open() (err error) {
	conf.mutex.Lock()
	defer conf.mutex.Unlock()

	// Parse IPs and control port number from environment variables
	intIP := utils.GetEnv("SEASIDE_ADDRESS", conf.Default.IP.String())
	extIP := utils.GetEnv("SEASIDE_EXTERNAL", intIP)

	// Parse and initialize tunnel IP and network fields
	tunnelNetwork := utils.GetEnv("SEASIDE_TUNNEL_NETWORK", DEFAULT_TUNNEL_NETWORK)
	conf.IP, conf.Network, err = net.ParseCIDR(tunnelNetwork)
	if err != nil {
		return fmt.Errorf("error parsing tunnel network address (%s): %v", tunnelNetwork, err)
	}

	// Check if tunnel network has enough available addresses to accommodate all viridians
	networkMask, networkLen := conf.Network.Mask.Size()
	availableTunnelNetworkBits := networkLen - networkMask
	if availableTunnelNetworkBits < REQUIRED_TUNNEL_NETWORK_BITS {
		return fmt.Errorf("not enough viridian addresses in tunnel network: %d bits < %d bits", availableTunnelNetworkBits, REQUIRED_TUNNEL_NETWORK_BITS)
	}

	// Create and open TUN device
	configuration := water.Config{DeviceType: water.TUN}
	configuration.Name = conf.name
	conf.Tunnel, err = water.New(configuration)
	if err != nil {
		return fmt.Errorf("error allocating TUN interface: %v", err)
	}

	// Open tunnel interface
	err = conf.openInterface(extIP)
	if err != nil {
		return fmt.Errorf("error creating tunnel interface: %v", err)
	}

	// Setup iptables forwarding rules
	apiPort := uint16(utils.GetIntEnv("SEASIDE_API_PORT", DEFAULT_API_PORT, 16))
	portPort := int32(utils.GetIntEnv("SEASIDE_PORT_PORT", DEFAULT_PORT_PORT, 32))
	typhoonPort := int32(utils.GetIntEnv("SEASIDE_TYPHOON_PORT", DEFAULT_TYPHOON_PORT, 32))
	err = conf.openForwarding(intIP, extIP, apiPort, portPort, typhoonPort)
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

	err := conf.closeForwarding()
	if err != nil {
		logrus.Errorf("Error closing forwarding: %v", err)
	}

	conf.closeInterface()
	if err != nil {
		logrus.Errorf("Error closing tunnel: %v", err)
	}

	conf.Tunnel.Close()
	if err != nil {
		logrus.Errorf("Error removing tunnel: %v", err)
	}
}
