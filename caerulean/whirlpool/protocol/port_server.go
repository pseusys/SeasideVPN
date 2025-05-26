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

	"github.com/pseusys/betterbuf"
	"github.com/sirupsen/logrus"
)

const PORT_INPUT_CHANNEL_BUFFER uint = 5

type PortServer struct {
	cipher     *crypto.Symmetric
	srcAddress net.IP
	peerID     uint16
	inputChan  chan *betterbuf.Buffer
	socket     *net.TCPConn
}

func NewPortServer(cipher *crypto.Symmetric, peerID uint16, peerIP net.IP, conn *net.TCPConn) *PortServer {
	return &PortServer{
		cipher:     cipher,
		srcAddress: peerIP,
		peerID:     peerID,
		inputChan:  make(chan *betterbuf.Buffer, PORT_INPUT_CHANNEL_BUFFER),
		socket:     conn,
	}
}

// Read reads data from the peer.
func (p *PortServer) Read(buffer *betterbuf.Buffer, viridianDict *users.ViridianDict, peerBytes []byte, tunIP *net.IP) (*betterbuf.Buffer, error) {
	encryptedHeaderLength := PORT_ANY_OTHER_HEADER + crypto.SymmetricCiphertextOverhead
	header := buffer.RebufferEnd(encryptedHeaderLength)
	s, err := io.ReadFull(p.socket, header.Slice())
	if err != nil {
		logrus.Errorf("packet header reading error: %v", err) // TODO: check if socket is closed!!
		return nil, nil
	}
	logrus.Debugf("Read %d bytes from viridian %d", s, p.peerID)

	msgType, dataLength, tailLength, err := parsePortAnyMessageHeader(p.cipher, header)
	if err != nil {
		logrus.Errorf("packet header parsing error: %v", err)
		return nil, nil
	}
	logrus.Debugf("Parsed packet header from viridian %d: type %d, data %d, tail %d", p.peerID, msgType, dataLength, tailLength)

	var value *betterbuf.Buffer
	if msgType == TYPE_DATA {
		dataBuffer := buffer.Rebuffer(encryptedHeaderLength, encryptedHeaderLength+int(dataLength))
		s, err := io.ReadFull(p.socket, dataBuffer.Slice())
		if err != nil {
			logrus.Errorf("packet data reading error: %v", err)
			return nil, nil
		}
		logrus.Debugf("Read packet data from viridian %d: length %d", p.peerID, s)

		_, err = io.CopyN(io.Discard, p.socket, int64(tailLength))
		if err != nil {
			logrus.Errorf("packet tail skipping error: %v", err)
			return nil, nil
		}
		logrus.Debugf("Read packet tail from viridian %d: length %d", p.peerID, tailLength)

		value, err = parsePortAnyData(p.cipher, dataBuffer)
		if err != nil {
			logrus.Errorf("packet data parsing error: %v", err)
			return nil, nil
		}
		logrus.Debugf("Parsed packet data from viridian %d", p.peerID)

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
func (p *PortServer) Write(data *betterbuf.Buffer, viridianDict *users.ViridianDict) error {
	defer PacketPool.Put(data)

	packetLength, packetSource, packetDestination, err := utils.ReadIPv4(data)
	if err != nil {
		return fmt.Errorf("reading packet information from viridian %d error: %v", p.peerID, err)
	}
	logrus.Debugf("Forwarding packet to viridian %d: length %d, from %v, to %v", p.peerID, packetLength, *packetSource, *packetDestination)

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

	encrypted, err := buildPortAnyData(p.cipher, data)
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
	packet, err := buildPortAnyTerm(p.cipher)
	if err != nil {
		return fmt.Errorf("error building term packet: %v", err)
	}
	defer PacketPool.Put(packet)

	_, err = p.socket.Write(packet.Slice())
	if err != nil {
		return fmt.Errorf("error writing term packet: %v", err)
	}

	return nil
}

// Serve starts the server and handles the callback.
func (p *PortServer) serveRead(ctx context.Context, packetChan chan *betterbuf.Buffer, errorChan chan error) {
	bytesID := []byte{0, 0}
	binary.BigEndian.PutUint16(bytesID, p.peerID)

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
			packet, err := p.Read(buffer, viridianDict, bytesID, &tunnelIP)

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

			// Packet parsing failed - continue listening
			if packet == nil {
				PacketPool.Put(buffer)
				continue
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

func (p *PortServer) serveWrite(base context.Context, errorChan chan error) {
	viridianDict, ok := users.FromContext(base)
	if !ok {
		errorChan <- fmt.Errorf("viridian dictionary not found in context: %v", base)
		return
	}

	for {
		select {
		case <-base.Done():
			return
		case packet := <-p.inputChan:
			err := p.Write(packet, viridianDict)
			if err != nil {
				errorChan <- err
				return
			}
		}
	}
}

func (p *PortServer) Serve(base context.Context, packetChan chan *betterbuf.Buffer) {
	localErrorChan := make(chan error)
	defer close(localErrorChan)

	ctx, cancel := context.WithCancel(base)
	defer cancel()

	go p.serveRead(ctx, packetChan, localErrorChan)
	go p.serveWrite(ctx, localErrorChan)

	select {
	case <-base.Done():
		logrus.Infof("Read operation from peer %d canceled due to context cancellation!", p.peerID)
	case err := <-localErrorChan:
		logrus.Errorf("Interrupting connection with peer %d because of the error: %v", p.peerID, err)
	}
}
