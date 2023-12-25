package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
)

const (
	BUFFER_OVERHEAD = 500
	HeaderLen       = 20
)

var (
	IOBUFFERSIZE   int // TODO: examine size of math.MaxUint16
	SEA_CONNECTION *net.UDPConn
)

func init() {
	buff, err := strconv.Atoi(MTU)
	if err != nil {
		logrus.Fatalln("Couldn't parse MTU:", MTU)
	}
	IOBUFFERSIZE = buff + BUFFER_OVERHEAD
}

type NetSettableLayerType interface {
	SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
}

func ReceivePacketsFromViridian(tunnel *water.Interface, tunnetwork *net.IPNet) {
	buffer := make([]byte, IOBUFFERSIZE)

	// Create objects for packet decoding
	serialBuffer := gopacket.NewSerializeBuffer()

	for {
		// Clear the serialization buffer
		serialBuffer.Clear()

		// Read IOBUFFERSIZE of data
		r, address, err := SEA_CONNECTION.ReadFromUDP(buffer)
		if err != nil || r == 0 {
			logrus.Errorf("Reading from viridian error (%d bytes read): %v", r, err)
			continue
		}

		// Deobfuscate packet
		data, userID, err := Deobfuscate(buffer[:r], false)
		if err != nil {
			logrus.Errorln("Deobfuscating packet error:", err)
			// SendMessageToUser(generated.UserControlResponseStatus_ERROR, address.IP, nil, true)
			continue
		}

		// Get the viridian we receive the packet from
		viridianID := []byte{0, 0}
		binary.BigEndian.PutUint16(viridianID, *userID)
		viridian, exists := VIRIDIANS[*userID]
		if !exists {
			logrus.Errorln("User not registered")
			// SendMessageToUser(generated.UserControlResponseStatus_ERROR, gateway.IP, nil, true)
			continue
		}

		// Decrypt packet
		raw, err := decryptPacket(data, &viridian)
		if err != nil {
			logrus.Errorln("Decrypting packet error:", err)
			// SendMessageToUser(generated.UserControlResponseStatus_ERROR, address.IP, nil, true)
			continue
		}

		// Decode all packet headers
		packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.NoCopy)
		if err := packet.ErrorLayer(); err != nil {
			logrus.Errorln("Error decoding some part of the packet:", err)
		}

		// Get IP layer header and change source IP
		netLayer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		logrus.Infof("Received %d bytes from viridian %v (src: %v, dst: %v)", netLayer.Length, address, netLayer.SrcIP, netLayer.DstIP)
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
			logrus.Errorln("Serializing packet error:", err)
			continue
		}

		// Write packet to tunnel
		s, err := tunnel.Write(serialBuffer.Bytes())
		if err != nil || s == 0 {
			logrus.Errorf("Writing to tunnel error (%d bytes written): %v", s, err)
			// SendMessageToUser(generated.UserControlResponseStatus_ERROR, gateway.IP, nil, true)
			continue
		}
	}
}

func decryptPacket(ciphertext []byte, viridian *Viridian) ([]byte, error) {
	viridian.expire.Reset(USER_LIFETIME)

	plaintext, err := DecryptSymmetrical(ciphertext, viridian.aead)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func SendPacketsToViridian(tunnel *water.Interface, tunnetwork *net.IPNet) {
	buffer := make([]byte, IOBUFFERSIZE)

	// Create objects for packet decoding
	serialBuffer := gopacket.NewSerializeBuffer()

	for {
		// Clear the serialization buffer
		serialBuffer.Clear()

		// Read IOBUFFERSIZE of data from tunnel
		r, err := tunnel.Read(buffer)
		if r == 0 && err != nil {
			logrus.Errorf("Reading from tunnel error (%d bytes read): %v", r, err)
			continue
		}
		raw := buffer[:r]

		// Decode all packet headers
		packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.NoCopy)
		if err := packet.ErrorLayer(); err != nil {
			logrus.Errorln("Error decoding some part of the packet:", err)
		}

		// Get IP layer header and change source IP
		netLayer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

		// Get the viridian we receive the packet from and set packet destination
		viridianID := binary.BigEndian.Uint16([]byte{netLayer.DstIP[2], netLayer.DstIP[3]})
		viridian, exists := VIRIDIANS[viridianID]
		if !exists {
			logrus.Errorln("User not registered")
			continue
		}

		// Resolve viridian address to send to
		gateway, err := net.ResolveUDPAddr(UDP, fmt.Sprintf("%s:%v", viridian.gateway.String(), *port))
		if err != nil {
			logrus.Errorln("Parsing return address error:", err)
			continue
		}

		netLayer.DstIP = viridian.address
		logrus.Infof("Sending %d bytes to viridian %v (src: %v, dst: %v)", netLayer.Length, gateway, netLayer.SrcIP, netLayer.DstIP)

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
			logrus.Errorln("Serializing packet error:", err)
			continue
		}

		// Encrypt packet
		encrypted, err := encryptPacket(serialBuffer.Bytes(), &viridian)
		if err != nil {
			logrus.Errorln("Encrypting packet error:", err)
			// SendMessageToUser(generated.UserControlResponseStatus_ERROR, gateway.IP, nil, true)
			continue
		}

		// Deobfuscate packet
		data, err := Obfuscate(encrypted, &viridianID, false)
		if err != nil {
			logrus.Errorln("Obfuscating packet error:", err)
			// SendMessageToUser(generated.UserControlResponseStatus_ERROR, address.IP, nil, true)
			continue
		}

		// Send packet to viridian
		s, err := SEA_CONNECTION.WriteToUDP(data, gateway)
		if err != nil || s == 0 {
			logrus.Errorf("Writing to viridian error (%d bytes written): %v", s, err)
			// SendMessageToUser(generated.UserControlResponseStatus_ERROR, gateway.IP, nil, true)
			continue
		}
	}
}

func encryptPacket(plaintext []byte, viridian *Viridian) ([]byte, error) {
	viridian.expire.Reset(USER_LIFETIME)

	ciphertext, err := EncryptSymmetrical(plaintext, viridian.aead)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}