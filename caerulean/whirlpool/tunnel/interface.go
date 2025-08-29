package tunnel

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// Create and open tunnel interface.
// Use "ip" commands ("link" and "addr") to setup tunnel configuration.
// Use MTU value received from environment variable if it is >= 0, use MTU of external network interface otherwise.
// Should be applied for TunnelConf object, receives tunnel configurations from it.
// Accept external IP address as a string.
// Return nil if interface opened successfully, error otherwise.
func (conf *TunnelConfig) openInterface(extIP string) error {
	// Cast tunnel name, ip and CIDR to string
	tunnelName := conf.Tunnel.Name()
	tunnelString := conf.IP.String()
	tunnelCIDR, _ := conf.Network.Mask.Size()

	// Receive MTU from environment or use MTU of external network interface and cast it to string
	if conf.mtu <= 0 {
		tunnelInterface, err := findInterfaceByIP(extIP)
		if err != nil {
			return fmt.Errorf("error resolving network addresses: %v", err)
		}
		conf.mtu = int32(tunnelInterface.MTU)
	}

	// Lookup tunnel link by name
	link, err := netlink.LinkByName(tunnelName)
	if err != nil {
		return fmt.Errorf("could not get link %s: %v", tunnelName, err)
	}

	// Setup tunnel interface MTU
	if err := netlink.LinkSetMTU(link, int(conf.mtu)); err != nil {
		return fmt.Errorf("error setting tunnel MTU: %v", err)
	}

	// Parse tunnel IP and CIDR
	addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", tunnelString, tunnelCIDR))
	if err != nil {
		return fmt.Errorf("invalid tunnel address: %v", err)
	}

	// Setup IP address for tunnel interface
	if err := netlink.AddrAdd(link, addr); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("error adding tunnel address: %v", err)
		}
	}

	// Enable tunnel interface
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("error setting tunnel UP: %v", err)
	}

	// Log and return no error
	logrus.Infof("Interface %s opened (IP: %s, MTU: %d)", tunnelName, tunnelString, conf.mtu)
	return nil
}

// Disable and remove tunnel interface.
// Use "ip" "link" command to remove interface.
// Should be applied for TunnelConf object, receives tunnel name from it.
func (conf *TunnelConfig) closeInterface() error {
	// Receive tunnel name
	tunnelName := conf.Tunnel.Name()

	// Lookup tunnel link by name
	link, err := netlink.LinkByName(tunnelName)
	if err != nil {
		return fmt.Errorf("could not get link %s: %v", tunnelName, err)
	}

	// Disable and remove tunnel
	if err := netlink.LinkSetDown(link); err != nil {
		return fmt.Errorf("error shutting down tunnel interface: %v", err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("error deleting tunnel interface: %v", err)
	}

	// Log interface closed
	logrus.Infof("Interface %s closed", tunnelName)
	return nil
}
