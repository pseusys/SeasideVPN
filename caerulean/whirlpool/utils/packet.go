package utils

import (
	"encoding/binary"
	"fmt"
	"net"
)

var (
	pseudoHeaderPool = CreateBufferPool(0, 12)
)

// CalculateChecksum computes the Internet checksum (RFC 1071).
func calculateChecksum(dataPieces ...*Buffer) uint16 {
	var sum uint32
	for _, data := range dataPieces {
		for i := 0; i < int(data.Length())-1; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(data.Reslice(uint(i), uint(i+2))))
		}
		if data.Length()%2 != 0 {
			sum += uint32(data.Get(data.Length()-1)) << 8
		}
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ReadIPv4(packet *Buffer) (uint16, *net.IP, *net.IP, error) {
	if packet.Length() < 20 {
		return 0, nil, nil, fmt.Errorf("packet too short for IPv4")
	}

	ihl := int((packet.Get(0) & 0x0F) * 4)
	if ihl < 20 {
		return 0, nil, nil, fmt.Errorf("invalid IPv4 header length")
	}

	sourceIP := net.IP(packet.Reslice(12, 16))
	destinationIP := net.IP(packet.Reslice(16, 20))
	totalLength := binary.BigEndian.Uint16(packet.Reslice(2, 4))
	return totalLength, &sourceIP, &destinationIP, nil
}

// UpdateIPv4 modifies source and destination IPs and fixes checksum.
func UpdateIPv4(packet *Buffer, newSrc, newDst *net.IP) error {
	if packet.Length() < 20 {
		return fmt.Errorf("packet too short for IPv4")
	}

	ihl := uint((packet.Get(0) & 0x0F) * 4)
	if ihl < 20 {
		return fmt.Errorf("invalid IPv4 header length")
	}

	ipHeader := packet.RebufferEnd(ihl)
	protocol := ipHeader.Get(9)

	// Modify source & destination IP
	if newSrc != nil {
		copy(ipHeader.Reslice(12, 16), newSrc.To4())
	}
	if newDst != nil {
		copy(ipHeader.Reslice(16, 20), newDst.To4())
	}

	// Zero out checksum before recalculating
	binary.BigEndian.PutUint16(ipHeader.Reslice(10, 12), 0)
	checksum := calculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader.Reslice(10, 12), checksum)

	// Fix transport layer checksum if applicable
	switch protocol {
	case 1: // ICMP
		updateICMPChecksum(ihl, packet)
	case 6, 17: // TCP or UDP
		updateTransportChecksum(ihl, packet, newSrc, newDst)
	}

	return nil
}

// UpdateICMPChecksum recalculates the ICMP checksum.
func updateICMPChecksum(ihl uint, packet *Buffer) error {
	icmpPacket := packet.RebufferStart(ihl)
	if icmpPacket.Length() < 4 {
		return fmt.Errorf("packet too short for ICMP (%d bytes)", icmpPacket.Length())
	}

	binary.BigEndian.PutUint16(icmpPacket.Reslice(2, 4), 0) // Zero out checksum before recalculating
	checksum := calculateChecksum(icmpPacket)
	binary.BigEndian.PutUint16(icmpPacket.Reslice(2, 4), checksum)

	return nil
}

// UpdateTransportChecksum recalculates TCP/UDP checksum based on new IPs.
func updateTransportChecksum(ihl uint, packet *Buffer, newSrc, newDst *net.IP) error {
	transportPacket := packet.RebufferStart(ihl)

	if packet.Length() < ihl+8 {
		return fmt.Errorf("packet too short for TCP/UDP (%d bytes)", transportPacket.Length())
	}

	protocol := packet.Get(9)
	var source, destination net.IP
	if newSrc != nil {
		source = *newSrc
	} else {
		source = packet.Reslice(12, 16)
	}
	if newDst != nil {
		destination = *newDst
	} else {
		destination = packet.Reslice(16, 20)
	}

	// Pseudo-header fields
	pseudoHeader := pseudoHeaderPool.Get()
	copy(pseudoHeader.Reslice(0, 4), source)
	copy(pseudoHeader.Reslice(4, 8), destination)
	pseudoHeader.Set(8, 0)
	pseudoHeader.Set(9, protocol)
	binary.BigEndian.PutUint16(pseudoHeader.Reslice(10, 12), uint16(transportPacket.Length()))

	binary.BigEndian.PutUint16(transportPacket.Reslice(2, 4), 0) // Zero out old checksum before recalculating
	checksum := calculateChecksum(pseudoHeader, transportPacket)
	binary.BigEndian.PutUint16(transportPacket.Reslice(2, 4), checksum)

	pseudoHeaderPool.Put(pseudoHeader)
	return nil
}
