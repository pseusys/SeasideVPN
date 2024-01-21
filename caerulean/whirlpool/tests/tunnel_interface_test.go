package tests

import (
	"main/tunnel"
	"net"
	"testing"

	"github.com/songgao/water"
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

	conf := tunnel.TunnelConfig{
		Tunnel:  tun,
		IP:      tunIP,
		Network: tunNetwork,
	}
	tunnel.OpenInterface(&conf, "127.0.0.1")
	test.Logf("tunnel interface created: %s", conf.Tunnel.Name())

	tunnelOpenedIface, err := net.InterfaceByName(conf.Tunnel.Name())
	if err != nil {
		test.Fatalf("tunnel interface not found: %v", err)
	}

	if tunnelOpenedIface.MTU != tunnel.MTU {
		test.Fatalf("tunnel interface setup incorrectly: %d != %d", tunnel.MTU, tunnelOpenedIface.MTU)
	}

	test.Logf("tunnel interface flags set: %s", tunnelOpenedIface.Flags.String())

	if (tunnelOpenedIface.Flags & net.FlagRunning) == 0 {
		test.Fatal("tunnel interface is not running")
	}

	if (tunnelOpenedIface.Flags & net.FlagUp) == 0 {
		test.Fatal("tunnel interface is not up")
	}

	tunnel.CloseInterface(&conf)

	tunnelClosedIface, err := net.InterfaceByName(conf.Tunnel.Name())
	if err == nil {
		test.Fatalf("tunnel interface found after deletion: %v", tunnelClosedIface.Index)
	}
}
