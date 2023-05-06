package main

import (
	"log"
	"os/exec"
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

// todo: try replacing with `nftables`
func ConfigureForwarding() {
	runCommand("sysctl", "net.ipv4.conf.tun0.forwarding=1")
	runCommand("iptables", "-A", "FORWARD", "-i", "tun0", "-o", "eth0", "-j", "ACCEPT")
	runCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "!", "-s", "10.5.0.0/24", "-o", "eth0", "-j", "MASQUERADE")
	log.Println("Forwarding configured:", "tun0 -> eth0")
}
