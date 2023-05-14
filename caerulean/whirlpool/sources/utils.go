package main

import (
	"net"

	"golang.org/x/net/ipv4"
)

// TODO: add udp header parsing
func CheckFromViridian(packet []byte, packetLength int, out_iface net.IP) (bool, *ipv4.Header, error) {
	header, err := ipv4.ParseHeader(packet[:packetLength])
	if err != nil {
		return false, nil, err
	}

	_, dport, err := ResolveIOPortsUDP(packet, packetLength)
	if err != nil {
		return false, header, err
	}

	return header.Protocol == UDP && header.Dst.Equal(out_iface) && dport == PORT, header, nil
}
