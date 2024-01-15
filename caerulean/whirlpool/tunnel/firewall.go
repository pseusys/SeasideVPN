package tunnel

import (
	"fmt"
	"os/exec"
	"strconv"

	"github.com/sirupsen/logrus"
)

func storeForwarding(conf *TunnelConfig) {
	command := exec.Command("iptables-save")
	command.Stdout = &conf.buffer
	err := command.Run()
	if err != nil {
		logrus.Errorf("Error running command %s: %v", command, err)
	}
}

func openForwarding(intIP, extIP, tunIface string, seaPort, netPort, ctrlPort int) error {
	netStr := strconv.Itoa(netPort)
	portStr := strconv.Itoa(seaPort)
	ctrlStr := strconv.Itoa(ctrlPort)

	intIface, err := findInterfaceByIP(intIP)
	if err != nil {
		return fmt.Errorf("error finding interface for internal IP %s: %v", intIP, err)
	}

	extIface, err := findInterfaceByIP(extIP)
	if err != nil {
		return fmt.Errorf("error finding interface for external IP %s: %v", extIP, err)
	}

	// Flush iptables rules
	runCommand("iptables", "-F")
	runCommand("iptables", "-t", "nat", "-F")
	runCommand("iptables", "-t", "mangle", "-F")
	// Accept packets to port network, control and whirlpool ports, also accept PING packets
	runCommand("iptables", "-A", "INPUT", "-p", "udp", "-d", intIP, "--dport", portStr, "-i", intIface, "-j", "ACCEPT")
	runCommand("iptables", "-A", "INPUT", "-p", "tcp", "-d", intIP, "--dport", ctrlStr, "-i", intIface, "-j", "ACCEPT")
	runCommand("iptables", "-A", "INPUT", "-p", "tcp", "-d", intIP, "--dport", netStr, "-i", intIface, "-j", "ACCEPT")
	runCommand("iptables", "-A", "INPUT", "-p", "icmp", "-d", intIP, "-i", intIface, "-j", "ACCEPT")
	runCommand("iptables", "-A", "INPUT", "-p", "tcp", "-i", "lo", "-j", "ACCEPT")
	// Else drop all input packets
	runCommand("iptables", "-P", "INPUT", "DROP")
	// Enable forwarding from tun0 to eth0 (forward)
	runCommand("iptables", "-A", "FORWARD", "-i", tunIface, "-o", extIface, "-j", "ACCEPT")
	// Enable forwarding from eth0 to tun0 (backward)
	runCommand("iptables", "-A", "FORWARD", "-i", extIface, "-o", tunIface, "-j", "ACCEPT")
	// Drop all other forwarding packets (e.g. from eth0 to eth0)
	runCommand("iptables", "-P", "FORWARD", "DROP")
	// Enable masquerade on all non-claimed output and input from and to eth0
	runCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", extIface, "-j", "MASQUERADE")

	logrus.Infoln("Forwarding configured:", intIface, "<->", tunIface, "<->", extIface)
	return nil
}

func closeForwarding(conf *TunnelConfig) {
	command := exec.Command("iptables-restore", "--counters")
	command.Stdin = &conf.buffer
	err := command.Run()
	if err != nil {
		logrus.Errorf("Error running command %s: %v", command, err)
	}
}
