package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"

	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

const (
	BUFFERSIZE = 2000
	MTU        = "1300" // TODO: revise!
	TUNNEL_IP  = "192.168.0.87/24"
)

var (
	ip   = flag.String("ip", "127.0.0.1", "External whirlpool IP")
	port = flag.Int("port", 1723, "UDP port for communication")
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

// TODO: restore after execution?
func ConfigureForwarding(externalInterface string, tunnelInterface string) {
	portStr := strconv.Itoa(*port)
	// Accept packets to port 1723, pass to VPN decoder
	runCommand("iptables", "-A", "INPUT", "-p", "udp", "-d", *ip, "--dport", portStr, "-i", externalInterface, "-j", "ACCEPT")
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

func makePublic(output *net.UDPConn, input *water.Interface) {
	buf := make([]byte, BUFFERSIZE)
	for {
		n, addr, err := output.ReadFromUDP(buf)
		header, _ := ipv4.ParseHeader(buf[:n])
		log.Printf("Received %d bytes from viridian %v: %+v\n", n, addr, header)
		if err != nil || n == 0 {
			log.Println("Error: ", err)
			continue
		}
		input.Write(buf[:n])
	}
}

func makePrivate(output *water.Interface, input *net.UDPConn, remote *net.UDPAddr) {
	packet := make([]byte, BUFFERSIZE)
	for {
		plen, err := output.Read(packet)
		if err != nil {
			break
		}
		header, _ := ipv4.ParseHeader(packet[:plen])
		log.Printf("Sending to viridian: %+v (%+v)\n", header, err)
		input.WriteToUDP(packet[:plen], remote)
	}
}

func main() {
	flag.Parse()
	if "" == *ip {
		flag.Usage()
		log.Fatalln("\nRemote server is not specified!")
	}

	tunnel, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatalln("Unable to allocate TUN interface:", err)
	}

	iname := tunnel.Name()
	AllocateInterface(iname, MTU, TUNNEL_IP)
	ConfigureForwarding("eth0", iname) // TODO: find the default interface name

	gateway, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%v", *ip, *port))
	if err != nil {
		log.Fatal(err)
	}

	connection, err := net.ListenUDP("udp4", gateway)
	if err != nil {
		log.Fatal(err)
	}

	defer connection.Close()
	go makePublic(connection, tunnel)

	go makePrivate(tunnel, connection, gateway)

	select {}
}
