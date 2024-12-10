package tunnel

import (
	"net"
	"testing"

	"github.com/songgao/water"
)

const (
	OPEN_INTERFACE_CYCLE_MTU  = 1500
	OPEN_INTERFACE_CYCLE_NAME = "testtun"
)

func TestOpenInterfaceCycle(test *testing.T) {
	tunIP, tunNetwork, err := net.ParseCIDR("10.0.0.25/24")
	if err != nil {
		test.Fatalf("error parsing tunnel network address (%s): %v", tunIP, err)
	}

	tun, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		test.Fatalf("error allocating TUN interface: %v", err)
	}

	conf := TunnelConfig{
		Tunnel:  tun,
		IP:      tunIP,
		Network: tunNetwork,
		mtu:     OPEN_INTERFACE_CYCLE_MTU,
		name:    OPEN_INTERFACE_CYCLE_NAME,
	}
	conf.openInterface("127.0.0.1")
	test.Logf("tunnel interface created: %s", conf.Tunnel.Name())

	tunnelOpenedIface, err := net.InterfaceByName(conf.Tunnel.Name())
	if err != nil {
		test.Fatalf("tunnel interface not found: %v", err)
	}

	expectedMTU := OPEN_INTERFACE_CYCLE_MTU
	if tunnelOpenedIface.MTU != expectedMTU {
		test.Fatalf("tunnel interface setup incorrectly: %d != %d", expectedMTU, tunnelOpenedIface.MTU)
	}

	expectedName := OPEN_INTERFACE_CYCLE_NAME
	if tunnelOpenedIface.Name != expectedName {
		test.Fatalf("tunnel interface setup incorrectly: %d != %d", expectedName, tunnelOpenedIface.Name)
	}

	test.Logf("tunnel interface flags set: %s", tunnelOpenedIface.Flags.String())

	if (tunnelOpenedIface.Flags & net.FlagRunning) == 0 {
		test.Fatal("tunnel interface is not running")
	}

	if (tunnelOpenedIface.Flags & net.FlagUp) == 0 {
		test.Fatal("tunnel interface is not up")
	}

	conf.closeInterface()

	tunnelClosedIface, err := net.InterfaceByName(conf.Tunnel.Name())
	if err == nil {
		test.Fatalf("tunnel interface found after deletion: %v", tunnelClosedIface.Index)
	}
}
