package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"main/crypto"
	"main/users"
	"math"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

// UDP connection for viridian messages accepting.
var SEA_CONNECTION *net.UDPConn

// Special type for checking IP packet layers - if they should use IP header in checksum calculation.
type netSettableLayerType interface {
	SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
}

// Initialize UDP connection for viridian messages accepting.
// Accept internal network address (as a string) and UDP port number.
// Return error if the connection wasn't initialized.
func InitializeSeasideConnection(internalAddress string, port int) error {
	// Resolve UDP address
	gateway, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", internalAddress, port))
	if err != nil {
		logrus.Fatalf("Error resolving local address: %v", err)
	}

	// Create connection
	SEA_CONNECTION, err = net.ListenUDP("udp4", gateway)
	if err != nil {
		logrus.Fatalf("Error resolving connection (%s): %v", gateway.String(), err)
	}

	// Return no error
	return nil
}

// Start receiving UDP VPN packets from viridians (internal interface, seaside port) and sending them to the internet.
// Accept Context for graceful termination, tunnel interface pointer and tunnel IP network address pointer.
// NB! this method is blocking, so it should be run as goroutine.
func ReceivePacketsFromViridian(ctx context.Context, tunnel *water.Interface, tunnetwork *net.IPNet) {
	buffer := make([]byte, math.MaxUint16)

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
		r, _, err := SEA_CONNECTION.ReadFromUDP(buffer)
		if err != nil || r == 0 {
			logrus.Errorf("Error reading from viridian (%d bytes read): %v", r, err)
			continue
		}

		// Read message subscription
		userID, err := crypto.UnsubscribeMessage(buffer[:r])
		if err != nil {
			logrus.Errorf("Error deobfuscating packet: %v", err)
			continue
		}

		// Get the viridian the packet belongs to
		viridianID := []byte{0, 0}
		binary.BigEndian.PutUint16(viridianID, *userID)
		viridian := users.GetViridian(*userID)
		if viridian == nil {
			logrus.Errorf("Error: user %d not registered", viridianID)
			continue
		}

		// Decode the packet
		raw, err := crypto.Decode(buffer[:r], viridian.AEAD)
		if err != nil {
			logrus.Errorf("Error decrypting packet: %v", err)
			continue
		}

		// Parse all packet headers
		packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.NoCopy)
		if err := packet.ErrorLayer(); err != nil {
			logrus.Errorf("Error decoding some part of the packet: %v", err)
		}

		// Get IP layer header and change source IP
		netLayer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		logrus.Infof("Received %d bytes from viridian %d (src: %v, dst: %v)", netLayer.Length, *userID, netLayer.SrcIP, netLayer.DstIP)
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
func SendPacketsToViridian(ctx context.Context, tunnel *water.Interface, tunnetwork *net.IPNet) {
	buffer := make([]byte, math.MaxUint16)

	// CCreate buffer for packet decoding
	serialBuffer := gopacket.NewSerializeBuffer()

	logrus.Debug("Sending packets to viridian started")
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
		viridian := users.GetViridian(viridianID)
		if viridian == nil {
			logrus.Errorf("Error: user %d not registered", viridianID)
			continue
		}

		// Resolve the viridian destination address
		gateway, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%v", viridian.Gateway.String(), viridian.Port))
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
		encrypted, err := crypto.Encrypt(serialBuffer.Bytes(), viridian.AEAD, &viridianID, false)
		if err != nil {
			logrus.Errorf("Error encrypting packet: %v", err)
			continue
		}

		// Send packet to viridian
		s, err := SEA_CONNECTION.WriteToUDP(encrypted, gateway)
		if err != nil || s == 0 {
			logrus.Errorf("Error writing to viridian (%d bytes written): %v", s, err)
			continue
		}
	}
}
