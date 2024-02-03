package tunnel

import (
	"fmt"
	"main/utils"
	"strconv"

	"github.com/sirupsen/logrus"
)

// MTU value for tunnel network interface.
var MTU int

// Initialize package variables from environment variables.
func init() {
	MTU = utils.GetIntEnv("SEASIDE_TUNNEL_MTU")
}

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
	tunnelIntMTU := MTU
	if MTU <= 0 {
		tunnelInterface, err := findInterfaceByIP(extIP)
		if err != nil {
			return fmt.Errorf("error resolving network addresses: %v", err)
		}
		tunnelIntMTU = tunnelInterface.MTU
	}
	tunnelMTU := strconv.Itoa(tunnelIntMTU)

	// Setup tunnel interface MTU
	runCommand("ip", "link", "set", "dev", tunnelName, "mtu", tunnelMTU)
	// Setup IP address for tunnel interface
	runCommand("ip", "addr", "add", fmt.Sprintf("%s/%d", tunnelString, tunnelCIDR), "dev", tunnelName)
	// Enable tunnel interfaces
	runCommand("ip", "link", "set", "dev", tunnelName, "up")

	// Log and return no error
	logrus.Infof("Interface %s opened (IP: %s, MTU: %s)", tunnelName, tunnelString, tunnelMTU)
	return nil
}

// Disable and remove tunnel interface.
// Use "ip" "link" command to remove interface.
// Should be applied for TunnelConf object, receives tunnel name from it.
func (conf *TunnelConfig) closeInterface() {
	// Receive tunnel name
	tunnelName := conf.Tunnel.Name()

	// Disable and remove tunnel
	runCommand("ip", "link", "set", "dev", tunnelName, "down")
	runCommand("ip", "link", "del", "dev", tunnelName)

	// Log interface closed
	logrus.Infof("Interface %s closed", tunnelName)
}
