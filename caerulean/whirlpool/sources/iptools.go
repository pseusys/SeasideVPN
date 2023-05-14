package main

import (
	"errors"
	"fmt"
	"net"
)

const (
	ETHERTYPE      = 0x0800
	UDP            = 0x11
	IP_HEADER_LEN  = 20
	UDP_HEADER_LEN = 28
)

func ResolveIOPortsUDP(packet []byte, packetLength int) (int, int, error) {
	if packetLength <= UDP_HEADER_LEN {
		return -1, -1, errors.New(fmt.Sprintf("Given packet size is less than UDP header size (%d)!", UDP_HEADER_LEN))
	}
	sport := (int(packet[20]) << 8) | int(packet[21])
	dport := (int(packet[22]) << 8) | int(packet[23])
	return sport, dport, nil
}

func IsSpecialNetworkAddress(address net.IP, network net.IPNet) bool {
	ip := address.To4()
	id := network.IP.To4()
	ms := network.Mask
	is_address := ip.Equal(id)
	is_first := ip[0] == id[0] && ip[1] == id[1] && ip[2] == id[2] && ip[3] == id[3]+1
	is_last := ip[0] == id[0]+ms[0] && ip[1] == id[1]+ms[1] && ip[2] == id[2]+ms[2] && ip[3] == id[3]+ms[3]
	return is_address || is_first || is_last
}
