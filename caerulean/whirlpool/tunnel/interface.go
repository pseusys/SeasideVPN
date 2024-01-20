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

func OpenInterface(conf *TunnelConfig) error {
	tunnelName := conf.Tunnel.Name()
	tunnelMTU := strconv.Itoa(MTU)
	tunnelString := conf.IP.String()
	tunnelCIDR, _ := conf.Network.Mask.Size()

	// Setup tunnel interface MTU
	RunCommand("ip", "link", "set", "dev", tunnelName, "mtu", tunnelMTU)
	// Setup IP address for tunnel interface
	RunCommand("ip", "addr", "add", fmt.Sprintf("%s/%d", tunnelString, tunnelCIDR), "dev", tunnelName)
	// Enable tunnel interfaces
	RunCommand("ip", "link", "set", "dev", tunnelName, "up")

	logrus.Infof("Interface %s opened (IP: %s, MTU: %s)", tunnelName, tunnelString, tunnelMTU)
	return nil
}

func CloseInterface(conf *TunnelConfig) {
	tunnelName := conf.Tunnel.Name()

	RunCommand("ip", "link", "set", "dev", tunnelName, "down")
	RunCommand("ip", "link", "del", "dev", tunnelName)

	logrus.Infof("Interface %s closed", tunnelName)
}
