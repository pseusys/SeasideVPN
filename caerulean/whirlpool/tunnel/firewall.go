package tunnel

import (
	"fmt"
	"main/users"
	"main/utils"
	"os/exec"
	"strconv"

	"github.com/sirupsen/logrus"
)

var (
	VPN_DATA_KBYTE_LIMIT_RULE []string
	CONTROL_PACKET_LIMIT_RULE []string
	HTTP_PACKET_LIMIT_RULE    []string
	ICMP_PACKET_LIMIT_RULE    []string
)

func init() {
	totalUsersNumber := int(users.MAX_TOTAL)
	burstMultiplier := utils.GetIntEnv("SEASIDE_BURST_LIMIT_MULTIPLIER")

	VPN_DATA_KBYTE_LIMIT_RULE = readLimit("SEASIDE_VPN_DATA_LIMIT", "%dkb/s", totalUsersNumber, burstMultiplier)
	CONTROL_PACKET_LIMIT_RULE = readLimit("SEASIDE_CONTROL_PACKET_LIMIT", "%d/sec", totalUsersNumber, burstMultiplier)
	HTTP_PACKET_LIMIT_RULE = readLimit("SEASIDE_HTTP_PACKET_LIMIT", "%d/sec", totalUsersNumber, burstMultiplier)
	ICMP_PACKET_LIMIT_RULE = readLimit("SEASIDE_ICMP_PACKET_LIMIT", "%d/sec", totalUsersNumber, burstMultiplier)
}

func readLimit(envVar, template string, userNumber, burstMultiplier int) []string {
	acceptRuleTemplate := []string{"-j", "ACCEPT"}
	hashlimitRuleTemplate := []string{"-m", "hashlimit", "--hashlimit-mode", "dstip,dstport"}
	limitNumber := utils.GetIntEnv(envVar) * userNumber
	if limitNumber > 0 {
		ruleSlice := []string{"--hashlimit-name", "vpnrate", "--hashlimit-upto", fmt.Sprintf(template, limitNumber), "--hashlimit-burst", strconv.Itoa(limitNumber * burstMultiplier)}
		return utils.ConcatSlices(hashlimitRuleTemplate, ruleSlice, acceptRuleTemplate)
	} else {
		return acceptRuleTemplate
	}
}

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
	runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "udp", "-d", intIP, "--dport", portStr, "-i", intIface}, VPN_DATA_KBYTE_LIMIT_RULE)...)
	runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "tcp", "-d", intIP, "--dport", ctrlStr, "-i", intIface}, CONTROL_PACKET_LIMIT_RULE)...)
	runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "tcp", "-d", intIP, "--dport", netStr, "-i", intIface}, HTTP_PACKET_LIMIT_RULE)...)
	runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "icmp", "-d", intIP, "-i", intIface}, ICMP_PACKET_LIMIT_RULE)...)
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

	logrus.Infof("Forwarding configured: %s <-> %s <-> %s", intIface, tunIface, extIface)
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
