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

func NewPortServer(cipher *crypto.Symmetric, peerID uint16, peerIP net.IP, conn *net.TCPConn) *PortServer {
	inputChan := make(chan *utils.Buffer, PORT_INPUT_CHANNEL_BUFFER)

	return &PortServer{
		cipher:     cipher,
		srcAddress: peerIP,
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
	s, err := io.ReadFull(p.socket, header.Slice())
	if err != nil {
		return nil, fmt.Errorf("packet header reading error: %v", err)
	}
	logrus.Debugf("Read %d bytes from viridian %d", s, p.peerID)

	msgType, dataLength, tailLength, err := p.core.ParseAnyMessageHeader(p.cipher, header)
	if err != nil {
		return nil, fmt.Errorf("packet header parsing error: %v", err)
	}
	logrus.Debugf("Parsed packet header from viridian %d: type %d, data %d, tail %d", p.peerID, msgType, dataLength, tailLength)

	var value *utils.Buffer
	if msgType == TYPE_DATA {
		dataBuffer := buffer.Rebuffer(encryptedHeaderLength, encryptedHeaderLength+int(dataLength))
		s, err := io.ReadFull(p.socket, dataBuffer.Slice())
		if err != nil {
			return nil, fmt.Errorf("packet data reading error: %v", err)
		}
		logrus.Debugf("Read packet data from viridian %d: length %d", p.peerID, s)

		value, err = p.core.ParseAnyData(p.cipher, dataBuffer)
		if err != nil {
			return nil, fmt.Errorf("packet data parsing error: %v", err)
		}
		logrus.Debugf("Parsed packet data from viridian %d", p.peerID)

		_, err = io.CopyN(io.Discard, p.socket, int64(tailLength))
		if err != nil {
			return nil, fmt.Errorf("packet tail skipping error: %v", err)
		}
		logrus.Debugf("Read packet tail from viridian %d: length %d", p.peerID, tailLength)

	} else if msgType == TYPE_TERMINATION {
		return nil, fmt.Errorf("connection with viridian %d terminated", p.peerID)
	} else {
		return nil, fmt.Errorf("unexpected message type received from viridian %d: %d", p.peerID, msgType)
	}

	viridian, ok := viridianDict.Get(p.peerID, users.PROTOCOL_PORT)
	if !ok {
		return nil, fmt.Errorf("viridian with ID %d not found", p.peerID)
	}
	logrus.Debugf("Viridian %d found: name '%s', identifier '%s'", p.peerID, viridian.Name, viridian.Identifier)

	packetLength, packetSource, packetDestination, err := utils.ReadIPv4(value)
	if err != nil {
		logrus.Errorf("Reading packet information from viridian %d error: %v", p.peerID, err)
		return nil, nil
	} else {
		copy(p.srcAddress, *packetSource)
	}
	logrus.Infof("Received %d bytes from viridian %d (src: %v, dst: %v)", packetLength, p.peerID, packetSource, packetDestination)

	newSrcIP := net.IPv4((*tunIP)[0], (*tunIP)[1], peerBytes[0], peerBytes[1])
	err = utils.UpdateIPv4(value, newSrcIP, nil)
	if err != nil {
		logrus.Errorf("Updating packet source from viridian %d error: %v", p.peerID, err)
		return nil, nil
	}
	logrus.Debugf("Updated packet from viridian %d, new source: %v", p.peerID, newSrcIP)

	return value, nil
}

// Write sends data to the peer.
func (p *PortServer) Write(data *utils.Buffer, viridianDict *users.ViridianDict) error {
	packetLength, packetSource, packetDestination, err := utils.ReadIPv4(data)
	if err != nil {
		return fmt.Errorf("reading packet information from viridian %d error: %v", p.peerID, err)
	}
	logrus.Debugf("Forwarding packet to viridian %d: length %d, from %v, to %v", p.peerID, packetLength, *packetSource, *packetDestination)

	defer PacketPool.Put(data)
	logrus.Infof("Sending %d bytes to viridian %d (src: %v, dst: %v)", packetLength, p.peerID, packetSource, p.srcAddress)

	viridian, ok := viridianDict.Get(p.peerID, users.PROTOCOL_PORT)
	if !ok {
		return fmt.Errorf("viridian with ID %d not found", p.peerID)
	}
	logrus.Debugf("Viridian %d found: name '%s', identifier '%s'", p.peerID, viridian.Name, viridian.Identifier)

	err = utils.UpdateIPv4(data, nil, p.srcAddress)
	if err != nil {
		logrus.Errorf("Updating packet destination from viridian %d error: %v", p.peerID, err)
		return nil
	}
	logrus.Debugf("Updated packet to viridian %d, new destination: %v", p.peerID, p.srcAddress)

	encrypted, err := p.core.buildAnyData(p.cipher, data)
	if err != nil {
		logrus.Errorf("Building data package for viridian error: %v", err)
		return nil
	}
	logrus.Debugf("Packet to viridian %d encrypted, new size: %d", p.peerID, encrypted.Length())

	s, err := p.socket.Write(encrypted.Slice())
	if err != nil {
		logrus.Errorf("Writing package for viridian error: %v", err)
		return nil
	}
	logrus.Debugf("Bytes written to viridian %d: %d", p.peerID, s)

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
func (s *PortServer) serveRead(ctx context.Context, packetChan chan *utils.Buffer, errorChan chan error) {
	bytesID := []byte{0, 0}
	binary.BigEndian.PutUint16(bytesID, s.peerID)

	viridianDict, ok := users.FromContext(ctx)
	if !ok {
		errorChan <- fmt.Errorf("viridian dictionary not found in context: %v", ctx)
		return
	}

	tunnelConfig, ok := tunnel.FromContext(ctx)
	if !ok {
		errorChan <- fmt.Errorf("tunnel config not found in context: %v", ctx)
		return
	}

	tunnelIP := tunnelConfig.IP.To4()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buffer := PacketPool.GetFull()
			packet, err := s.Read(buffer, viridianDict, bytesID, &tunnelIP)

			if err != nil {
				// Return buffer to pool before sending error
				PacketPool.Put(buffer)
				select {
				case <-ctx.Done():
					return
				default:
					errorChan <- err
					return
				}
			}

			// Send packet and defer buffer return after usage
			select {
			case <-ctx.Done():
				// If context is canceled while waiting to send packet, return buffer and exit
				PacketPool.Put(buffer)
				return
			default:
				packetChan <- packet
				// The receiver is responsible for returning the buffer after usage.
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
	localErrorChan := make(chan error)
	defer close(localErrorChan)

	ctx, cancel := context.WithCancel(base)
	defer cancel()

	go s.serveRead(ctx, packetChan, localErrorChan)
	go s.serveWrite(ctx, localErrorChan)

	select {
	case <-base.Done():
		logrus.Infof("Read operation from peer %d canceled due to context cancellation!", s.peerID)
	case err := <-localErrorChan:
		logrus.Errorf("Interrupting connection with peer %d because of the error: %v", s.peerID, err)
	}
}
