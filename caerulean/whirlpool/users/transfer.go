package users

import (
	"context"
	"encoding/binary"
	"fmt"
	"main/crypto"
	"math"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

// Special type for checking IP packet layers - if they should use IP header in checksum calculation.
type netSettableLayerType interface {
	SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
}

// Start receiving UDP VPN packets from viridians (internal interface, seaside port) and sending them to the internet.
// Accept Context for graceful termination, tunnel interface pointer and tunnel IP network address pointer.
// NB! this method is blocking, so it should be run as goroutine.
func (dict *ViridianDict) ReceivePacketsFromViridian(ctx context.Context, userID uint16, connection *net.UDPConn, tunnel *water.Interface, tunnetwork *net.IPNet) {
	buffer := make([]byte, math.MaxUint16)

	viridianID := []byte{0, 0}
	binary.BigEndian.PutUint16(viridianID, userID)

	// Create buffer for packet decoding
	serialBuffer := gopacket.NewSerializeBuffer()

	logrus.Debug("Receiving packets from viridian started")
	for {
		// Handle graceful termination
		select {
		case <-ctx.Done():
			logrus.Debug("Receiving packets from viridian stopped")
			return
		default: // do nothing
		}

		// Clear the serialization buffer
		serialBuffer.Clear()

		// Read packet from UDP connection
		r, _, err := connection.ReadFromUDP(buffer)
		if err != nil || r == 0 {
			logrus.Errorf("Error reading from viridian (%d bytes read): %v", r, err)
			continue
		}

		// Get the viridian the packet belongs to
		viridian, ok := dict.Get(userID)
		if !ok {
			logrus.Errorf("Error: user %d not registered", userID)
			continue
		}

		// Decode the packet
		raw, err := crypto.Decrypt(buffer[:r], viridian.AEAD)
		if err != nil {
			logrus.Errorf("Error decrypting packet: %v", err)
			continue
		}

		// Parse all packet headers
		packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.NoCopy)
		if err := packet.ErrorLayer(); err != nil {
			logrus.Errorf("Error decoding some part of the packet: %v", err)
			continue
		}

		// Get IP layer header and change source IP
		netLayer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		logrus.Infof("Received %d bytes from viridian %d (src: %v, dst: %v)", netLayer.Length, userID, netLayer.SrcIP, netLayer.DstIP)
		netLayer.SrcIP = net.IPv4(tunnetwork.IP[0], tunnetwork.IP[1], viridianID[0], viridianID[1])

		// Set the network layer to all the layers that require a network layer
		for _, layer := range packet.Layers() {
			netSettableLayer, ok := layer.(netSettableLayerType)
			if ok {
				netSettableLayer.SetNetworkLayerForChecksum(netLayer)
			}
		}

		// Serialize the packet
		err = gopacket.SerializePacket(serialBuffer, gopacket.SerializeOptions{ComputeChecksums: true}, packet)
		if err != nil {
			logrus.Errorf("Error serializing packet: %v", err)
			continue
		}

		// Write packet to tunnel
		s, err := tunnel.Write(serialBuffer.Bytes())
		if err != nil || s == 0 {
			logrus.Errorf("Error writing to tunnel (%d bytes written): %v", s, err)
			continue
		}
	}
}

// Start receiving packets from the internet (external interface) and sending them to viridians.
// Accept Context for graceful termination, tunnel interface pointer and tunnel IP network address pointer.
// NB! this method is blocking, so it should be run as goroutine.
func (dict *ViridianDict) SendPacketsToViridians(ctx context.Context, tunnel *water.Interface, tunnetwork *net.IPNet) {
	buffer := make([]byte, math.MaxUint16)

	// CCreate buffer for packet decoding
	serialBuffer := gopacket.NewSerializeBuffer()

	logrus.Debug("Sending packets to viridians started")
	for {
		// Handle graceful termination
		select {
		case <-ctx.Done():
			logrus.Debug("Sending packets to viridian stopped")
			return
		default: // do nothing
		}

		// Clear the serialization buffer
		serialBuffer.Clear()

		// Read data from the tunnel
		r, err := tunnel.Read(buffer)
		if r == 0 && err != nil {
			logrus.Errorf("Error reading from tunnel error (%d bytes read): %v", r, err)
			continue
		}

		// Parse all packet headers
		packet := gopacket.NewPacket(buffer[:r], layers.LayerTypeIPv4, gopacket.NoCopy)
		if err := packet.ErrorLayer(); err != nil {
			logrus.Errorf("Error decoding some part of the packet: %v", err)
		}

		// Get packet IP layer header
		netLayer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

		// Get the viridian the packet was received from
		viridianID := binary.BigEndian.Uint16([]byte{netLayer.DstIP[2], netLayer.DstIP[3]})
		viridian, ok := dict.Get(viridianID)
		if !ok {
			logrus.Errorf("Error: user %d not registered", viridianID)
			continue
		}

		// Resolve the viridian destination address
		gateway, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", viridian.Gateway.String(), viridian.Port))
		if err != nil {
			logrus.Errorf("Error parsing return address: %v", err)
			continue
		}

		// Change packet IP layer destination address
		netLayer.DstIP = viridian.Address
		logrus.Infof("Sending %d bytes to viridian %d (src: %v, dst: %v)", netLayer.Length, viridianID, netLayer.SrcIP, netLayer.DstIP)

		// Set the network layer to all the layers that require a network layer
		for _, layer := range packet.Layers() {
			netSettableLayer, ok := layer.(netSettableLayerType)
			if ok {
				netSettableLayer.SetNetworkLayerForChecksum(netLayer)
			}
		}

		// Serialize the packet
		err = gopacket.SerializePacket(serialBuffer, gopacket.SerializeOptions{ComputeChecksums: true}, packet)
		if err != nil {
			logrus.Errorf("Error serializing packet: %v", err)
			continue
		}

		// Encrypt packet
		encrypted, err := crypto.Encrypt(serialBuffer.Bytes(), viridian.AEAD)
		if err != nil {
			logrus.Errorf("Error encrypting packet: %v", err)
			continue
		}

		// Send packet to viridian
		s, err := viridian.SeaConn.WriteToUDP(encrypted, gateway)
		if err != nil || s == 0 {
			logrus.Errorf("Error writing to viridian (%d bytes written): %v", s, err)
			continue
		}
	}
}
