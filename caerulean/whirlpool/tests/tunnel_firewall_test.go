package tests

import (
	"main/tunnel"
	"testing"
)

func TestStoreForwardingCycle(test *testing.T) {
	var conf tunnel.TunnelConfig

	beforesave := tunnel.RunCommand("iptables", "-vnL", "INPUT")
	test.Logf("IP tables configuration before saving: %s", beforesave)

	tunnel.StoreForwarding(&conf)

	tunnel.RunCommand("iptables", "-F")
	tunnel.RunCommand("iptables", "-A", "INPUT", "-j", "LOG")

	intermediate := tunnel.RunCommand("iptables", "-vnL", "INPUT")
	if beforesave == intermediate {
		test.Fatalf("IP tables alteration changed nothing: %s == %s", intermediate, beforesave)
	}
	test.Logf("IP tables configuration after alteration: %s", intermediate)

	tunnel.CloseForwarding(&conf)

	aftersave := tunnel.RunCommand("iptables", "-vnL", "INPUT")
	if aftersave != beforesave {
		test.Fatalf("IP tables were not restored: %s != %s", aftersave, beforesave)
	}
}
