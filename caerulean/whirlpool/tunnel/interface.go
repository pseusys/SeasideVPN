package tunnel

import (
	"fmt"
	"main/utils"
	"strconv"

	"github.com/sirupsen/logrus"
)

var MTU int

func init() {
	MTU = utils.GetIntEnv("SEASIDE_TUNNEL_MTU")
}

func (conf *TunnelConfig) openInterface(extIP string) error {
	tunnelName := conf.Tunnel.Name()
	tunnelString := conf.IP.String()
	tunnelCIDR, _ := conf.Network.Mask.Size()

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

	logrus.Infof("Interface %s opened (IP: %s, MTU: %s)", tunnelName, tunnelString, tunnelMTU)
	return nil
}

func (conf *TunnelConfig) closeInterface() {
	tunnelName := conf.Tunnel.Name()

	runCommand("ip", "link", "set", "dev", tunnelName, "down")
	runCommand("ip", "link", "del", "dev", tunnelName)

	logrus.Infof("Interface %s closed", tunnelName)
}
