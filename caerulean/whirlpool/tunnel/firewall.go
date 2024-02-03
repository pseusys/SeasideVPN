package tunnel

import (
	"fmt"
	"main/users"
	"main/utils"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// VPN packet limiting rules (as string arrays)
var (
	VPN_DATA_KBYTE_LIMIT_RULE []string
	CONTROL_PACKET_LIMIT_RULE []string
	HTTP_PACKET_LIMIT_RULE    []string
	ICMP_PACKET_LIMIT_RULE    []string
)

// Initialize package variables from environment variables.
func init() {
	totalUserNumber := int(users.MAX_TOTAL)
	burstMultiplier := utils.GetIntEnv("SEASIDE_BURST_LIMIT_MULTIPLIER")

	VPN_DATA_KBYTE_LIMIT_RULE = readLimit("SEASIDE_VPN_DATA_LIMIT", "%dkb/s", totalUserNumber, burstMultiplier)
	CONTROL_PACKET_LIMIT_RULE = readLimit("SEASIDE_CONTROL_PACKET_LIMIT", "%d/sec", totalUserNumber, burstMultiplier)
	HTTP_PACKET_LIMIT_RULE = readLimit("SEASIDE_HTTP_PACKET_LIMIT", "%d/sec", totalUserNumber, burstMultiplier)
	ICMP_PACKET_LIMIT_RULE = readLimit("SEASIDE_ICMP_PACKET_LIMIT", "%d/sec", totalUserNumber, burstMultiplier)
}

// Create "limit" iptable rule appendix (as a string array).
// Accepts environment variable name and template string where the value will be inserted (packet/second or kbyte/second, etc.).
// Also accepts maximum number of user supported by VPN and burst multiplier (integers).
// Burst multiplier is applied when large amount of data comes at the same time, doesn't last for long.
// At that time, packet limit is getting multiplied by this multiplier.
// Returns rule appendix string array.
func readLimit(envVar, template string, userNumber, burstMultiplier int) []string {
	acceptRuleTemplate := []string{"-j", "ACCEPT"}
	hashlimitRuleTemplate := []string{"-m", "hashlimit", "--hashlimit-mode", "dstip,dstport"}
	limitNumber := utils.GetIntEnv(envVar) * userNumber
	if limitNumber > 0 {
		ruleSlice := []string{"--hashlimit-name", strings.ToLower(envVar), "--hashlimit-upto", fmt.Sprintf(template, limitNumber), "--hashlimit-burst", strconv.Itoa(limitNumber * burstMultiplier)}
		return utils.ConcatSlices(hashlimitRuleTemplate, ruleSlice, acceptRuleTemplate)
	} else {
		return acceptRuleTemplate
	}
}

// Store iptables configuration.
// Use iptables-store command to store iptables configurations as bytes.
// Should be applied for TunnelConf object, store the configurations in .buffer field.
func (conf *TunnelConfig) storeForwarding() {
	command := exec.Command("iptables-save")
	command.Stdout = &conf.buffer
	err := command.Run()
	if err != nil {
		logrus.Errorf("Error running command %s: %v", command, err)
	}
}

// Setup iptables configuration for VPN usage.
// First, flush all iptables rules, setup allowed incoming packet patters and drop all the other packets.
// Then, setup forwarding from external to tunnel interface and back, also enabling masquerade for external interface outputs.
// Accept internal and external IP addresses as strings, seaside, network and control ports as integers.
// Return error if configuration was not successful, nil otherwise.
func (conf *TunnelConfig) openForwarding(intIP, extIP string, seaPort, netPort, ctrlPort int) error {
	// Prepare interface names and port numbers as strings
	tunIface := conf.Tunnel.Name()
	netStr := strconv.Itoa(netPort)
	portStr := strconv.Itoa(seaPort)
	ctrlStr := strconv.Itoa(ctrlPort)

	// Find internal network interface name
	intIface, err := findInterfaceByIP(intIP)
	if err != nil {
		return fmt.Errorf("error finding interface for internal IP %s: %v", intIP, err)
	}
	intName := intIface.Name

	// Find external network interface name
	extIface, err := findInterfaceByIP(extIP)
	if err != nil {
		return fmt.Errorf("error finding interface for external IP %s: %v", extIP, err)
	}
	extName := extIface.Name

	// Flush iptables rules
	runCommand("iptables", "-F")
	runCommand("iptables", "-t", "raw", "-F")
	runCommand("iptables", "-t", "nat", "-F")
	runCommand("iptables", "-t", "mangle", "-F")
	// Accept packets to port network, control and whirlpool ports, also accept PING packets
	runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "udp", "-d", intIP, "--dport", portStr, "-i", intName}, VPN_DATA_KBYTE_LIMIT_RULE)...)
	runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "tcp", "-d", intIP, "--dport", ctrlStr, "-i", intName}, CONTROL_PACKET_LIMIT_RULE)...)
	runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "tcp", "-d", intIP, "--dport", netStr, "-i", intName}, HTTP_PACKET_LIMIT_RULE)...)
	runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "icmp", "-d", intIP, "-i", intName}, ICMP_PACKET_LIMIT_RULE)...)
	// Else drop all input packets
	runCommand("iptables", "-P", "INPUT", "DROP")
	// Enable forwarding from tunnel interface to external interface (forward)
	runCommand("iptables", "-A", "FORWARD", "-i", tunIface, "-o", extName, "-j", "ACCEPT")
	// Enable forwarding from external interface to tunnel interface (backward)
	runCommand("iptables", "-A", "FORWARD", "-i", extName, "-o", tunIface, "-j", "ACCEPT")
	// Drop all other forwarding packets (e.g. from external interface to external interface)
	runCommand("iptables", "-P", "FORWARD", "DROP")
	// Enable masquerade on all non-claimed output and input from and to external interface
	runCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", extName, "-j", "MASQUERADE")

	// Return no error
	logrus.Infof("Forwarding configured: %s <-> %s <-> %s", intName, tunIface, extName)
	return nil
}

// Restore iptables configuration.
// Use iptables-restore command to restore iptables configurations from bytes.
// Should be applied for TunnelConf object, restore the configurations from .buffer field.
func (conf *TunnelConfig) closeForwarding() {
	command := exec.Command("iptables-restore", "--counters")
	command.Stdin = &conf.buffer
	err := command.Run()
	if err != nil {
		logrus.Errorf("Error running command %s: %v", command, err)
	}
}
