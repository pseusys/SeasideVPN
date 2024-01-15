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

func openInterface(conf *TunnelConfig) error {
	tunnelName := conf.Tunnel.Name()
	tunnelMTU := strconv.Itoa(MTU)
	tunnelString := conf.IP.String()
	tunnelCIDR, _ := conf.Network.Mask.Size()

	// Setup tunnel interface MTU
	runCommand("ip", "link", "set", "dev", tunnelName, "mtu", tunnelMTU)
	// Setup IP address for tunnel interface
	runCommand("ip", "addr", "add", fmt.Sprintf("%s/%d", tunnelString, tunnelCIDR), "dev", tunnelName)
	// Enable tunnel interfaces
	runCommand("ip", "link", "set", "dev", tunnelName, "up")

	logrus.Infof("Interface %s opened (IP: %s, MTU: %s)", tunnelName, tunnelString, tunnelMTU)
	return nil
}

func closeInterface(conf *TunnelConfig) {
	tunnelName := conf.Tunnel.Name()

	runCommand("ip", "link", "set", "dev", tunnelName, "down")
	runCommand("ip", "link", "del", "dev", tunnelName)

	logrus.Infof("Interface %s closed", tunnelName)
}
