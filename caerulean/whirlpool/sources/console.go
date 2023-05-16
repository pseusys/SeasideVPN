package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
)

const (
	MTU  = "1300" // TODO: revise!
	MARK = 87
)

func runCommand(command string, args ...string) {
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Command %s output: %s\n", command, output)
		log.Fatal("Running command error:", err)
	}
}

func AllocateInterface(name string, tun_ip *net.IP, tun_net *net.IPNet) {
	cidr, _ := tun_net.Mask.Size()

	// Setup tunnel interface MTU
	runCommand("ip", "link", "set", "dev", name, "mtu", MTU)
	// Setup IP address for tunnel interface
	runCommand("ip", "addr", "add", fmt.Sprintf("%s/%d", tun_ip.String(), cidr), "dev", name)
	// Enable tunnel interfaces
	runCommand("ip", "link", "set", "dev", name, "up")

	log.Println("Interface allocated:", name)
}

func ConfigureForwarding(externalInterface string, tunnelInterface string, tun_ip *net.IP) {
	portStr := strconv.Itoa(*input)
	markStr := strconv.Itoa(MARK)

	// Flush iptables rules
	runCommand("iptables", "-F")
	runCommand("iptables", "-t", "nat", "-F")
	runCommand("iptables", "-t", "mangle", "-F")
	// Accept packets to port 1723, pass to VPN decoder
	runCommand("iptables", "-A", "INPUT", "-p", "udp", "-m", "state", "--state", "NEW", "-d", *ip, "--dport", portStr, "-i", externalInterface, "-j", "ACCEPT")
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
	// Seting default route for table 87 through tunnel interface IP
	runCommand("ip", "route", "add", "table", markStr, "default", "via", tun_ip.String(), "dev", tunnelInterface)
	// Forwarding packets marked with 87 with table number 87
	runCommand("ip", "rule", "add", "fwmark", markStr, "table", markStr)
	// Flushing routing cache
	runCommand("ip", "route", "flush", "cache")

	log.Println("Forwarding configured:", externalInterface, "<->", tunnelInterface)
}
