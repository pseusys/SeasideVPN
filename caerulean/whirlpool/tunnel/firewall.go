package tunnel

import (
	"fmt"
	"main/utils"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// Create "limit" iptable rule appendix (as a string array).
// Accept environment variable name and template string where the value will be inserted (packet/second or kbyte/second, etc.).
// Also accept maximum number of user supported by VPN and burst multiplier (integers).
// Burst multiplier is applied when large amount of data comes at the same time, doesn't last for long.
// At that time, packet limit is getting multiplied by this multiplier.
// Return rule appendix string array.
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
// Should be applied for TunnelConf object.
// Accept internal and external IP addresses as strings, seaside, network and control ports as integers.
// Return error if configuration was not successful, nil otherwise.
func (conf *TunnelConfig) openForwarding(intIP, extIP string, ctrlPort int) error {
	// Prepare interface names and port numbers as strings
	tunIface := conf.Tunnel.Name()
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
	// Accept localhost connections
	runCommand("iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT")
	runCommand("iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
	// Allow all the connections that are already established
	runCommand("iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	runCommand("iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT")
	// Accept SSH connections
	runCommand("iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT")
	runCommand("iptables", "-A", "OUTPUT", "-p", "tcp", "--sport", "22", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT")
	// Accept packets to port network, control and whirlpool ports, also accept PING packets
	runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "udp", "-d", intIP, "-i", intName}, conf.vpnDataKbyteLimitRule)...)
	runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "tcp", "-d", intIP, "--dport", ctrlStr, "-i", intName}, conf.controlPacketLimitRule)...)
	runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "icmp", "-d", intIP, "-i", intName}, conf.icmpPacketPACKETLimitRules)...)
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
	runCommand("iptables", "-F")
	command := exec.Command("iptables-restore", "--counters")
	command.Stdin = &conf.buffer
	err := command.Run()
	if err != nil {
		logrus.Errorf("Error running command %s: %v", command, err)
	}
}
