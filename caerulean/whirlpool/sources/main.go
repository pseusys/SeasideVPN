package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os/exec"

	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

const (
	BUFFERSIZE = 2000
	MTU        = "1300"
)

var (
	localIP  = flag.String("local", "", "Local tun interface IP/MASK like 192.168.3.3/24")
	remoteIP = flag.String("remote", "", "Remote server (external) IP like 8.8.8.8")
	port     = flag.Int("port", 1723, "UDP port for communication")
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

func ConfigureForwarding() {
	// Accept packets to port 1723, pass to VPN decoder
	runCommand("iptables", "-A", "INPUT", "-p", "udp", "-d", "11.0.0.11", "--dport", "1723", "-i", "eth0", "-j", "ACCEPT")
	// Else drop all input packets
	runCommand("iptables", "-P", "INPUT", "DROP")
	// Enable forwarding from tun0 to eth0 (forward)
	runCommand("iptables", "-A", "FORWARD", "-i", "tun0", "-o", "eth0", "-j", "ACCEPT")
	// Enable forwarding from eth0 to tun0 (backward)
	runCommand("iptables", "-A", "FORWARD", "-i", "eth0", "-o", "tun0", "-j", "ACCEPT")
	// Drop all other forwarding packets (e.g. from eth0 to eth0)
	runCommand("iptables", "-P", "FORWARD", "DROP")
	// Enable masquerade on all non-claimed output and input from and to eth0
	runCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE")
	// Log setup finished
	log.Println("Forwarding configured:", "tun0 -> eth0")
}

func forwardFromUDPToTunnel(output *net.UDPConn, input *water.Interface) {
	buf := make([]byte, BUFFERSIZE)
	for {
		n, addr, err := output.ReadFromUDP(buf)
		header, _ := ipv4.ParseHeader(buf[:n])
		log.Printf("Received %d bytes from %v: %+v\n", n, addr, header)
		if err != nil || n == 0 {
			log.Println("Error: ", err)
			continue
		}
		input.Write(buf[:n])
	}
}

func forwardFromTunnelToUDP(output *water.Interface, input *net.UDPConn, remote *net.UDPAddr) {
	packet := make([]byte, BUFFERSIZE)
	for {
		plen, err := output.Read(packet)
		if err != nil {
			break
		}
		header, _ := ipv4.ParseHeader(packet[:plen])
		log.Printf("Sending to remote: %+v (%+v)\n", header, err)
		input.WriteToUDP(packet[:plen], remote)
	}
}

func main() {
	flag.Parse()
	if "" == *localIP {
		flag.Usage()
		log.Fatalln("\nLocal ip is not specified")
	}
	if "" == *remoteIP {
		flag.Usage()
		log.Fatalln("\nRemote server is not specified")
	}

	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatalln("Unable to allocate TUN interface:", err)
	}

	iname := iface.Name()
	AllocateInterface(iname, MTU, *localIP)
	ConfigureForwarding()

	remoteAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%v", *remoteIP, *port))
	if err != nil {
		log.Fatal(err)
	}

	s, err := net.ResolveUDPAddr("udp4", fmt.Sprintf(":%v", *port))
	if err != nil {
		log.Fatal(err)
	}

	connection, err := net.ListenUDP("udp4", s)
	if err != nil {
		log.Fatal(err)
	}

	defer connection.Close()
	go forwardFromUDPToTunnel(connection, iface)

	go forwardFromTunnelToUDP(iface, connection, remoteAddr)

	select {}
}
