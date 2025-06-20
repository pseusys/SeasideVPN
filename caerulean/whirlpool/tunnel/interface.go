package tunnel

import (
	"fmt"
	"strconv"

	"github.com/sirupsen/logrus"
)

// Create and open tunnel interface.
// Use "ip" commands ("link" and "addr") to setup tunnel configuration.
// Use MTU value received from environment variable if it is >= 0, use MTU of external network interface otherwise.
// Should be applied for TunnelConf object, receives tunnel configurations from it.
// Accept external IP address as a string.
// Return nil if interface opened successfully, error otherwise.
func (conf *TunnelConfig) openInterface(extIP string) error {
	// Cast sunnel name, ip and CIDR to string
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
	tunnelMTU := strconv.FormatInt(int64(conf.mtu), 10)

	// Setup tunnel interface MTU
	_, err := runCommand("ip", "link", "set", "dev", tunnelName, "mtu", tunnelMTU)
	if err != nil {
		return fmt.Errorf("error setting tunnel MTU: %v", err)
	}

	// Setup IP address for tunnel interface
	_, err = runCommand("ip", "addr", "add", fmt.Sprintf("%s/%d", tunnelString, tunnelCIDR), "dev", tunnelName)
	if err != nil {
		return fmt.Errorf("error setting tunnel IP address: %v", err)
	}

	// Enable tunnel interfaces
	_, err = runCommand("ip", "link", "set", "dev", tunnelName, "up")
	if err != nil {
		return fmt.Errorf("error setting tunnel UP: %v", err)
	}

	// Log and return no error
	logrus.Infof("Interface %s opened (IP: %s, MTU: %s)", tunnelName, tunnelString, tunnelMTU)
	return nil
}

// Disable and remove tunnel interface.
// Use "ip" "link" command to remove interface.
// Should be applied for TunnelConf object, receives tunnel name from it.
func (conf *TunnelConfig) closeInterface() error {
	// Receive tunnel name
	tunnelName := conf.Tunnel.Name()

	// Disable and remove tunnel
	_, err := runCommand("ip", "link", "set", "dev", tunnelName, "down")
	if err != nil {
		return fmt.Errorf("error shutting down tunnel interface: %v", err)
	}

	_, err = runCommand("ip", "link", "del", "dev", tunnelName)
	if err != nil {
		return fmt.Errorf("error deleting tunnel interface: %v", err)
	}

	// Log interface closed
	logrus.Infof("Interface %s closed", tunnelName)
	return nil
}
