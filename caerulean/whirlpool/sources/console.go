package main

import (
	"log"
	"os/exec"
	"strconv"
)

func runCommand(command string, args ...string) {
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Command %s output: %s\n", command, output)
		log.Fatal("Running command error:", err)
	}
}

func AllocateInterface(name string, mtu string, interface_ip string) {
	runCommand("ip", "link", "set", "dev", name, "mtu", mtu)
	runCommand("ip", "addr", "add", interface_ip, "dev", name)
	runCommand("ip", "link", "set", "dev", name, "up")
	log.Println("Interface allocated:", name)
}

func ConfigureForwarding(externalInterface string, tunnelInterface string) {
	portStr := strconv.Itoa(*port)
	runCommand("iptables", "-F")
	runCommand("iptables", "-t", "nat", "-F")
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
	// Log setup finished
	log.Println("Forwarding configured:", externalInterface, "<->", tunnelInterface)
}
