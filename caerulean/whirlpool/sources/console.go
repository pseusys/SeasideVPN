package main

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	MTU           = "1500"
	MARK          = 87
	ADDR_INTF_STR = `(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/\d\d) dev (?P<iface>[a-zA-Z0-9_]+).*src (?P<addr>(?:[0-9]{1,3}\.){3}[0-9]{1,3}) .*`
)

var ADDR_INTF_REGEXP = regexp.MustCompile(ADDR_INTF_STR)

func runCommand(cmd string, args ...string) string {
	command := exec.Command(cmd, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		logrus.Errorf("Command %s output: %s", cmd, output)
		logrus.Fatalln("Running command error:", err)
	}
	return string(output)
}

func AllocateInterface(name string, tunnelIP *net.IP, tunnelNetwork *net.IPNet) {
	cidr, _ := tunnelNetwork.Mask.Size()

	// Setup tunnel interface MTU
	runCommand("ip", "link", "set", "dev", name, "mtu", MTU)
	// Setup IP address for tunnel interface
	runCommand("ip", "addr", "add", fmt.Sprintf("%s/%d", tunnelIP.String(), cidr), "dev", name)
	// Enable tunnel interfaces
	runCommand("ip", "link", "set", "dev", name, "up")

	logrus.Infof("Interface %s allocated (MTU: %s, buffer: %d)", name, MTU, IOBUFFERSIZE)
}

func ConfigureForwarding(externalInterface string, internalInterface string, tunnelInterface string, tunnelIP *net.IP) {
	netStr := strconv.Itoa(*network)
	portStr := strconv.Itoa(*port)
	ctrlStr := strconv.Itoa(*control)
	markStr := strconv.Itoa(MARK)

	// Flush iptables rules
	runCommand("iptables", "-F")
	runCommand("iptables", "-t", "nat", "-F")
	runCommand("iptables", "-t", "mangle", "-F")
	// Accept packets to port network, control and whirlpool ports, also accept PING packets
	runCommand("iptables", "-A", "INPUT", "-p", "udp", "-d", *iIP, "--dport", portStr, "-i", internalInterface, "-j", "ACCEPT")
	runCommand("iptables", "-A", "INPUT", "-p", "tcp", "-d", *iIP, "--dport", ctrlStr, "-i", internalInterface, "-j", "ACCEPT")
	runCommand("iptables", "-A", "INPUT", "-p", "tcp", "-d", *iIP, "--dport", netStr, "-i", internalInterface, "-j", "ACCEPT")
	runCommand("iptables", "-A", "INPUT", "-p", "icmp", "-d", *iIP, "-i", internalInterface, "-j", "ACCEPT")
	// Else drop all input packets
	runCommand("iptables", "-P", "INPUT", "DROP")
	// Enable forwarding from tun0 to eth0 (forward)
	runCommand("iptables", "-A", "FORWARD", "-i", tunnelInterface, "-o", externalInterface, "-j", "ACCEPT")
	// Enable forwarding from eth0 to tun0 (backward)
	runCommand("iptables", "-A", "FORWARD", "-i", externalInterface, "-o", tunnelInterface, "-j", "ACCEPT")
	// Drop all other forwarding packets (e.g. from eth0 to eth0)
	runCommand("iptables", "-P", "FORWARD", "DROP")
	// Enable masquerade on all non-claimed output and input from and to eth0
	runCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", externalInterface, "-j", "MASQUERADE")

	// Set mark 87 to all packets, incoming via eth0 interface
	runCommand("iptables", "-t", "mangle", "-A", "PREROUTING", "-m", "state", "--state", "ESTABLISHED,RELATED", "-i", externalInterface, "-j", "MARK", "--set-mark", markStr)
	// Clear routing table number 87
	runCommand("ip", "route", "flush", "table", markStr)
	// Setting default route for table 87 through tunnel interface IP
	runCommand("ip", "route", "add", "table", markStr, "default", "via", tunnelIP.String(), "dev", tunnelInterface)
	// Forwarding packets marked with 87 with table number 87
	runCommand("ip", "rule", "add", "fwmark", markStr, "table", markStr)
	// Flushing routing cache
	runCommand("ip", "route", "flush", "cache")

	logrus.Infoln("Forwarding configured:", internalInterface, "<->", tunnelInterface, "<->", externalInterface)
}

func FindAddress(address string) (string, error) {
	interfaces := strings.Split(runCommand("ip", "route"), "\n")
	for _, line := range interfaces {
		result := ADDR_INTF_REGEXP.FindStringSubmatch(line)
		if len(result) == 3 && result[2] == address {
			return result[1], nil
		}
	}
	return "", errors.New("no valid interfaces found")
}
