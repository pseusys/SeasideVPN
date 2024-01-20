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

var SEA_CONNECTION *net.UDPConn

type NetSettableLayerType interface {
	SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
}

func InitializeSeasideConnection() error {
	gateway, err := net.ResolveUDPAddr(UDP, fmt.Sprintf("%s:%d", INTERNAL_ADDRESS, SEASIDE_PORT))
	if err != nil {
		logrus.Fatalf("Error resolving local address: %v", err)
	}

	SEA_CONNECTION, err = net.ListenUDP(UDP, gateway)
	if err != nil {
		logrus.Fatalf("Error resolving connection (%s): %v", gateway.String(), err)
	}

	return nil
}

func ReceivePacketsFromViridian(ctx context.Context, tunnel *water.Interface, tunnetwork *net.IPNet) {
	buffer := make([]byte, math.MaxUint16)

	// Create objects for packet decoding
	serialBuffer := gopacket.NewSerializeBuffer()

	logrus.Debug("Receiving packets from viridian started")
	for {
		select {
		case <-ctx.Done():
			logrus.Debug("Receiving packets from viridian stopped")
			return
		default: // do nothing
		}

		// Clear the serialization buffer
		serialBuffer.Clear()

		// Read IOBUFFERSIZE of data
		r, _, err := SEA_CONNECTION.ReadFromUDP(buffer)
		if err != nil || r == 0 {
			logrus.Errorf("Error reading from viridian (%d bytes read): %v", r, err)
			continue
		}

		// Deobfuscate packet
		userID, err := crypto.UnsubscribeMessage(buffer[:r])
		if err != nil {
			logrus.Errorf("Error deobfuscating packet: %v", err)
			continue
		}

		// Get the viridian we receive the packet from
		viridianID := []byte{0, 0}
		binary.BigEndian.PutUint16(viridianID, *userID)
		viridian := users.GetViridian(*userID)
		if viridian == nil {
			logrus.Errorf("Error: user %d not registered", viridianID)
			continue
		}

		// Decrypt packet
		raw, err := crypto.Decode(buffer[:r], true, viridian.AEAD)
		if err != nil {
			logrus.Errorf("Error decrypting packet: %v", err)
			continue
		}

		// Decode all packet headers
		packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.NoCopy)
		if err := packet.ErrorLayer(); err != nil {
			logrus.Errorf("Error decoding some part of the packet: %v", err)
		}

		// Get IP layer header and change source IP
		netLayer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		logrus.Infof("Received %d bytes from viridian %d (src: %v, dst: %v)", netLayer.Length, *userID, netLayer.SrcIP, netLayer.DstIP)
		netLayer.SrcIP = net.IPv4(tunnetwork.IP[0], tunnetwork.IP[1], viridianID[0], viridianID[1])

		// Set this network layer to all the layers that require a network layer
		for _, layer := range packet.Layers() {
			netSettableLayer, ok := layer.(NetSettableLayerType)
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

func SendPacketsToViridian(ctx context.Context, tunnel *water.Interface, tunnetwork *net.IPNet) {
	buffer := make([]byte, math.MaxUint16)

	// Create objects for packet decoding
	serialBuffer := gopacket.NewSerializeBuffer()

	logrus.Debug("Sending packets to viridian started")
	for {
		select {
		case <-ctx.Done():
			logrus.Debug("Sending packets to viridian stopped")
			return
		default: // do nothing
		}

		// Clear the serialization buffer
		serialBuffer.Clear()

		// Read data from tunnel
		r, err := tunnel.Read(buffer)
		if r == 0 && err != nil {
			logrus.Errorf("Error reading from tunnel error (%d bytes read): %v", r, err)
			continue
		}

		// Decode all packet headers
		packet := gopacket.NewPacket(buffer[:r], layers.LayerTypeIPv4, gopacket.NoCopy)
		if err := packet.ErrorLayer(); err != nil {
			logrus.Errorf("Error decoding some part of the packet: %v", err)
		}

		// Get IP layer header and change source IP
		netLayer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

		// Get the viridian we receive the packet from and set packet destination
		viridianID := binary.BigEndian.Uint16([]byte{netLayer.DstIP[2], netLayer.DstIP[3]})
		viridian := users.GetViridian(viridianID)
		if viridian == nil {
			logrus.Errorf("Error: user %d not registered", viridianID)
			continue
		}

		// Resolve viridian address to send to
		gateway, err := net.ResolveUDPAddr(UDP, fmt.Sprintf("%s:%v", viridian.Gateway.String(), viridian.Port))
		if err != nil {
			logrus.Errorf("Error parsing return address: %v", err)
			continue
		}

		netLayer.DstIP = viridian.Address
		logrus.Infof("Sending %d bytes to viridian %d (src: %v, dst: %v)", netLayer.Length, viridianID, netLayer.SrcIP, netLayer.DstIP)

		// Set this network layer to all the layers that require a network layer
		for _, layer := range packet.Layers() {
			netSettableLayer, ok := layer.(NetSettableLayerType)
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
