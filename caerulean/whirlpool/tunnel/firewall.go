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

const DEFAULT_HASHLIMIT_VALUE = -1

// Create "limit" iptable rule appendix (as a string array).
// Accept environment variable name and template string where the value will be inserted (packet/second or kbyte/second, etc.).
// Also accept maximum number of user supported by VPN and burst multiplier (integers).
// Burst multiplier is applied when large amount of data comes at the same time, doesn't last for long.
// At that time, packet limit is getting multiplied by this multiplier.
// Return rule appendix string array.
func readLimit(envVar, template string, userNumber int32, burstMultiplier uint32) []string {
	acceptRuleTemplate := []string{"-j", "ACCEPT"}
	hashlimitRuleTemplate := []string{"-m", "hashlimit", "--hashlimit-mode", "dstip,dstport"}
	limitNumber := int32(utils.GetIntEnv(envVar, DEFAULT_HASHLIMIT_VALUE, 32)) * userNumber
	if limitNumber > 0 {
		ruleSlice := []string{"--hashlimit-name", strings.ToLower(envVar), "--hashlimit-upto", fmt.Sprintf(template, limitNumber), "--hashlimit-burst", strconv.FormatUint(uint64(limitNumber)*uint64(burstMultiplier), 10)}
		return utils.ConcatSlices(hashlimitRuleTemplate, ruleSlice, acceptRuleTemplate)
	} else {
		return acceptRuleTemplate
	}
}

// Flush all the IP tables.
// This includes filter, raw, nat and mangle tables.
func flushIPTables() error {
	_, err := runCommand("iptables", "-F")
	if err != nil {
		return fmt.Errorf("error flushing filter table: %v", err)
	}

	_, err = runCommand("iptables", "-t", "raw", "-F")
	if err != nil {
		return fmt.Errorf("error flushing raw table: %v", err)
	}

	_, err = runCommand("iptables", "-t", "nat", "-F")
	if err != nil {
		return fmt.Errorf("error flushing nat table: %v", err)
	}

	_, err = runCommand("iptables", "-t", "mangle", "-F")
	if err != nil {
		return fmt.Errorf("error flushing mangle table: %v", err)
	}

	return nil
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
// First, flush all iptables rules, setup allowed incoming packet patterns and drop all the other packets.
// Then, setup forwarding from external to tunnel interface and back, also enabling masquerade for external interface outputs.
// Should be applied for TunnelConf object.
// Accept internal and external IP addresses as strings, seaside, network and control ports as integers.
// Return error if configuration was not successful, nil otherwise.
func (conf *TunnelConfig) openForwarding(intIP, extIP string, apiPort uint16, portPort, typhoonPort int32) error {
	// Prepare interface names and port numbers as strings
	tunIface := conf.Tunnel.Name()
	apiStr := strconv.FormatUint(uint64(apiPort), 10)

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

	logrus.Debugln("Looking for iptables configurations...")
	maxViridians := utils.GetIntEnv("SEASIDE_MAX_VIRIDIANS", users.DEFAULT_MAX_VIRIDIANS, 32)
	maxAdmins := utils.GetIntEnv("SEASIDE_MAX_ADMINS", users.DEFAULT_MAX_ADMINS, 32)
	maxTotal := int32(maxViridians + maxAdmins)
	burstMultiplier := uint32(utils.GetIntEnv("SEASIDE_BURST_LIMIT_MULTIPLIER", DEFAULT_BURST_MULTIPLIER, 32))

	logrus.Debugln("Building iptables limits...")
	vpnDataKbyteLimitRule := readLimit("SEASIDE_VPN_DATA_LIMIT", "%dkb/s", maxTotal, burstMultiplier)
	controlPacketLimitRule := readLimit("SEASIDE_CONTROL_PACKET_LIMIT", "%d/sec", maxTotal, burstMultiplier)
	icmpPacketPacketLimitRules := readLimit("SEASIDE_ICMP_PACKET_LIMIT", "%d/sec", maxTotal, burstMultiplier)

	// Flush iptables rules
	err = flushIPTables()
	if err != nil {
		return fmt.Errorf("error flushing IP tables: %v", err)
	}

	// Accept localhost connections
	_, err = runCommand("iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	_, err = runCommand("iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	// Accept admin connections to private ports (e.g. SSH, HTTP, etc.)
	_, err = runCommand("iptables", "-A", "INPUT", "-p", "tcp", "--dport", "0:1024", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	_, err = runCommand("iptables", "-A", "OUTPUT", "-p", "tcp", "--sport", "0:1024", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	// Allow all the connections that are already established
	_, err = runCommand("iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	_, err = runCommand("iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	// Accept packets to port network, control and whirlpool ports, also accept PING packets
	if typhoonPort != -1 {
		typhoonStr := strconv.FormatUint(uint64(typhoonPort), 10)
		_, err = runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "udp", "-d", intIP, "--dport", typhoonStr, "-i", intName}, controlPacketLimitRule)...)
		if err != nil {
			return err
		}

		_, err = runCommand("iptables", "-A", "INPUT", "-p", "udp", "-d", intIP, "--dport", typhoonStr, "-i", intName, "-j", "DROP")
		if err != nil {
			return err
		}
	}

	_, err = runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "udp", "-d", intIP, "-i", intName}, vpnDataKbyteLimitRule)...)
	if err != nil {
		return err
	}

	if portPort != -1 {
		portStr := strconv.FormatUint(uint64(portPort), 10)
		_, err = runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "tcp", "-d", intIP, "--dport", portStr, "-i", intName}, controlPacketLimitRule)...)
		if err != nil {
			return err
		}

		_, err = runCommand("iptables", "-A", "INPUT", "-p", "tcp", "-d", intIP, "--dport", portStr, "-i", intName, "-j", "DROP")
		if err != nil {
			return err
		}
	}

	_, err = runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "tcp", "-d", intIP, "--dport", apiStr, "-i", intName}, controlPacketLimitRule)...)
	if err != nil {
		return err
	}

	_, err = runCommand("iptables", "-A", "INPUT", "-p", "tcp", "-d", intIP, "--dport", apiStr, "-i", intName, "-j", "DROP")
	if err != nil {
		return err
	}

	_, err = runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "tcp", "-d", intIP, "-i", intName}, vpnDataKbyteLimitRule)...)
	if err != nil {
		return err
	}

	_, err = runCommand("iptables", utils.ConcatSlices([]string{"-A", "INPUT", "-p", "icmp", "-d", intIP, "-i", intName}, icmpPacketPacketLimitRules)...)
	if err != nil {
		return err
	}

	_, err = runCommand("iptables", "-A", "INPUT", "-p", "icmp", "-d", intIP, "-i", intName, "-j", "DROP")
	if err != nil {
		return err
	}

	// Else drop all input packets
	_, err = runCommand("iptables", "-P", "INPUT", "DROP")
	if err != nil {
		return err
	}

	// Enable forwarding from tunnel interface to external interface (forward)
	_, err = runCommand("iptables", "-A", "FORWARD", "-i", tunIface, "-o", extName, "-j", "ACCEPT")
	if err != nil {
		return err
	}

	// Enable forwarding from external interface to tunnel interface (backward)
	_, err = runCommand("iptables", "-A", "FORWARD", "-i", extName, "-o", tunIface, "-j", "ACCEPT")
	if err != nil {
		return err
	}

	// Drop all other forwarding packets (e.g. from external interface to external interface)
	_, err = runCommand("iptables", "-P", "FORWARD", "DROP")
	if err != nil {
		return err
	}

	// Enable masquerade on all non-claimed output and input from and to external interface
	_, err = runCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", extName, "-j", "MASQUERADE")
	if err != nil {
		return err
	}

	// Return no error
	logrus.Infof("Forwarding configured: %s <-> %s <-> %s", intName, tunIface, extName)
	return nil
}

// Restore iptables configuration.
// Use iptables-restore command to restore iptables configurations from bytes.
// Should be applied for TunnelConf object, restore the configurations from .buffer field.
func (conf *TunnelConfig) closeForwarding() error {
	if conf.buffer.Len() > 0 {
		command := exec.Command("iptables-restore")
		command.Stdin = &conf.buffer
		err := command.Run()
		if err != nil {
			return fmt.Errorf("error running command %s: %v", command, err)
		}
	} else {
		err := flushIPTables()
		if err != nil {
			return fmt.Errorf("error flushing IP tables: %v", err)
		}
	}
	return nil
}
