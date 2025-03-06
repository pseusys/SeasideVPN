package protocol

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"main/crypto"
	"main/tunnel"
	"main/users"
	"main/utils"
	"net"

	"github.com/sirupsen/logrus"
)

const PORT_INPUT_CHANNEL_BUFFER uint = 5

type PortServer struct {
	cipher     *crypto.Symmetric
	srcAddress net.IP
	peerID     uint16
	inputChan  chan *utils.Buffer
	core       *PortCore
	socket     *net.TCPConn
}

func NewPortServer(cipher *crypto.Symmetric, peerID uint16, conn *net.TCPConn) *PortServer {
	inputChan := make(chan *utils.Buffer, PORT_INPUT_CHANNEL_BUFFER)

	return &PortServer{
		cipher:     cipher,
		srcAddress: nil,
		peerID:     peerID,
		inputChan:  inputChan,
		core:       newPortCore(PORT_DEFAULT_TIMEOUT),
		socket:     conn,
	}
}

// Read reads data from the peer.
func (p *PortServer) Read(buffer *utils.Buffer, viridianDict *users.ViridianDict, peerBytes []byte, tunIP *net.IP) (*utils.Buffer, error) {
	encryptedHeaderLength := ANY_OTHER_HEADER + crypto.SymmetricCiphertextOverhead
	header := buffer.RebufferEnd(encryptedHeaderLength)
	_, err := io.ReadFull(p.socket, header.Slice())
	if err != nil {
		return nil, err
	}

	msgType, dataLength, tailLength, err := p.core.ParseAnyMessageHeader(p.cipher, header)
	if err != nil {
		return nil, err
	}

	var value *utils.Buffer
	if msgType == TYPE_DATA {
		dataBuffer := buffer.Rebuffer(encryptedHeaderLength, encryptedHeaderLength+uint(dataLength)+crypto.SymmetricCiphertextOverhead)
		_, err := io.ReadFull(p.socket, dataBuffer.Slice())
		if err != nil {
			return nil, err
		}

		value, err = p.core.ParseAnyData(p.cipher, dataBuffer)
		if err != nil {
			return nil, err
		}

		_, err = io.CopyN(io.Discard, p.socket, int64(tailLength))
		if err != nil {
			return nil, err
		}

	} else if msgType == TYPE_TERMINATION {
		return nil, fmt.Errorf("connection with viridian %d terminated", p.peerID)
	} else {
		return nil, fmt.Errorf("unexpected message type received from viridian %d: %d", p.peerID, msgType)
	}

	_, ok := viridianDict.Get(p.peerID, users.PROTOCOL_PORT)
	if !ok {
		return nil, fmt.Errorf("viridian with ID %d not found", p.peerID)
	}

	packetLength, packetSource, packetDestination, err := utils.ReadIPv4(value)
	if err != nil {
		logrus.Errorf("Reading packet information from viridian %d error: %v", p.peerID, err)
		return nil, nil
	}

	logrus.Infof("Received %d bytes from viridian %d (src: %v, dst: %v)", packetLength, p.peerID, packetSource, packetDestination)

	newSrcIP := net.IPv4((*tunIP)[0], (*tunIP)[1], peerBytes[0], peerBytes[1])
	err = utils.UpdateIPv4(value, &newSrcIP, nil)
	if err != nil {
		logrus.Errorf("Updating packet source from viridian %d error: %v", p.peerID, err)
		return nil, nil
	}

	return value, nil
}

// Write sends data to the peer.
func (p *PortServer) Write(data *utils.Buffer, viridianDict *users.ViridianDict) error {
	packetLength, packetSource, _, err := utils.ReadIPv4(data)
	if err != nil {
		return fmt.Errorf("reading packet information from viridian %d error: %v", p.peerID, err)
	}

	defer PacketPool.Put(data)
	logrus.Infof("Sending %d bytes to viridian %d (src: %v, dst: %v)", packetLength, p.peerID, packetSource, p.srcAddress)

	_, ok := viridianDict.Get(p.peerID, users.PROTOCOL_PORT)
	if !ok {
		return fmt.Errorf("viridian with ID %d not found", p.peerID)
	}

	err = utils.UpdateIPv4(data, nil, &p.srcAddress)
	if err != nil {
		logrus.Errorf("Updating packet destination from viridian %d error: %v", p.peerID, err)
		return nil
	}

	encrypted, err := p.core.buildAnyData(p.cipher, data)
	if err != nil {
		logrus.Errorf("Building data package for viridian error: %v", err)
		return nil
	}

	_, err = p.socket.Write(encrypted.Slice())
	if err != nil {
		logrus.Errorf("Writing package for viridian error: %v", err)
		return nil
	}

	return nil
}

// Close closes the peer connection.
func (p *PortServer) Terminate() error {
	packet, err := p.core.buildAnyTerm(p.cipher)
	defer PacketPool.Put(packet)
	if err != nil {
		return fmt.Errorf("error building term packet: %v", err)
	}

	_, err = p.socket.Write(packet.Slice())
	if err != nil {
		return fmt.Errorf("error writing term packet: %v", err)
	}

	return nil
}

// Serve starts the server and handles the callback.
func (s *PortServer) serveRead(base context.Context, packetChan chan *utils.Buffer, errorChan chan error) {
	bytesID := []byte{0, 0}
	binary.BigEndian.PutUint16(bytesID, s.peerID)

	viridianDict, ok := users.FromContext(base)
	if !ok {
		errorChan <- fmt.Errorf("viridian dictionary not found in context: %v", base)
		return
	}

	tunnelConfig, ok := tunnel.FromContext(base)
	if !ok {
		errorChan <- fmt.Errorf("tunnel config not found in context: %v", base)
		return
	}

	for {
		select {
		case <-base.Done():
			return
		default:
			buffer := PacketPool.Get()
			packet, err := s.Read(buffer, viridianDict, bytesID, &tunnelConfig.IP)

			if err != nil {
				// Return buffer to pool before sending error
				PacketPool.Put(buffer)
				errorChan <- err
				return
			}

			// Send packet and defer buffer return after usage
			select {
			case packetChan <- packet:
				// The receiver is responsible for returning the buffer after usage.
			case <-base.Done():
				// If context is canceled while waiting to send packet, return buffer and exit
				PacketPool.Put(buffer)
				return
			}
		}
	}
}

func (s *PortServer) serveWrite(base context.Context, errorChan chan error) {
	viridianDict, ok := users.FromContext(base)
	if !ok {
		errorChan <- fmt.Errorf("viridian dictionary not found in context: %v", base)
		return
	}

	for {
		select {
		case <-base.Done():
			return
		case packet := <-s.inputChan:
			err := s.Write(packet, viridianDict)
			if err != nil {
				errorChan <- err
				return
			}
		}
	}
}

func (s *PortServer) Serve(base context.Context, packetChan chan *utils.Buffer) {
	ctx, cancel := context.WithCancel(base)
	defer cancel()

	localErrorChan := make(chan error)
	defer close(localErrorChan)

	go s.serveRead(ctx, packetChan, localErrorChan)
	go s.serveWrite(ctx, localErrorChan)

	for {
		select {
		case <-base.Done():
			logrus.Infof("Read operation from peer %d canceled due to context cancellation!", s.peerID)
			return
		case err := <-localErrorChan:
			logrus.Errorf("Interrupting connection with peer %d because of the error: %v", s.peerID, err)
			return
		}
	}
}
