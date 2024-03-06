package tunnel

import "testing"

func TestStoreForwardingCycle(test *testing.T) {
	var conf TunnelConfig

	beforesave := runCommand("iptables", "-vnL", "INPUT")
	test.Logf("IP tables configuration before saving: %s", beforesave)

	conf.storeForwarding()

	runCommand("iptables", "-F")
	runCommand("iptables", "-A", "INPUT", "-j", "LOG")

	intermediate := runCommand("iptables", "-vnL", "INPUT")
	if beforesave == intermediate {
		test.Fatalf("IP tables alteration changed nothing: %s == %s", intermediate, beforesave)
	}
	test.Logf("IP tables configuration after alteration: %s", intermediate)

	conf.closeForwarding()

	aftersave := runCommand("iptables", "-vnL", "INPUT")
	if aftersave != beforesave {
		test.Fatalf("IP tables were not restored: %s != %s", aftersave, beforesave)
	}
}
