package protocol

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"main/crypto"
	"main/tunnel"
	"main/users"
	"main/utils"
	"math"
	"net"
	"sync"
	"time"

	"github.com/pseusys/betterbuf"
	"github.com/sirupsen/logrus"
)

const TYPHOON_INPUT_CHANNEL_BUFFER uint = 16

type TyphoonConsistencyPart struct {
	packetNumber uint32
	nextIn       uint32
}

type TyphoonServer struct {
	cipher         *crypto.Symmetric
	srcAddress     net.IP
	peerID         uint16
	inputChan      chan *betterbuf.Buffer
	listener       *net.UDPConn
	socket         *net.UDPConn
	defaultTimeout uint32
	maxRetries     uint
	srtt           uint32
	rttvar         uint32
	previousSent   uint32
	previousNextIn uint32
	coreMutex      sync.Mutex
}

func NewTyphoonServer(cipher *crypto.Symmetric, peerID uint16, peerIP net.IP, lstnr, conn *net.UDPConn) *TyphoonServer {
	return &TyphoonServer{
		cipher:         cipher,
		srcAddress:     peerIP,
		peerID:         peerID,
		inputChan:      make(chan *betterbuf.Buffer, TYPHOON_INPUT_CHANNEL_BUFFER),
		listener:       lstnr,
		socket:         conn,
		defaultTimeout: TYPHOON_DEFAULT_TIMEOUT,
		maxRetries:     TYPHOON_MAX_RETRIES,
		srtt:           0,
		rttvar:         0,
		previousSent:   0,
		previousNextIn: 0,
	}
}

// Internal server functions:

func (t *TyphoonServer) GetRTT() uint32 {
	var rtt uint32
	if t.srtt > 0 {
		rtt = t.srtt
	} else {
		rtt = TYPHOON_DEFAULT_RTT
	}
	return min(max(rtt, TYPHOON_MIN_RTT), TYPHOON_MAX_RTT)
}

func (t *TyphoonServer) GetTimeout() uint32 {
	var timeout uint32
	if t.srtt > 0 && t.rttvar > 0 {
		timeout = t.srtt + uint32(TYPHOON_RTT_MULT*float64(t.rttvar))
	} else {
		timeout = TYPHOON_DEFAULT_TIMEOUT
	}
	return min(max(timeout, TYPHOON_MIN_TIMEOUT), TYPHOON_MAX_TIMEOUT)
}

func (t *TyphoonServer) updateTimeout(rtt uint32) {
	t.coreMutex.Lock()
	defer t.coreMutex.Unlock()

	if t.srtt == 0 || t.rttvar == 0 {
		t.srtt = rtt
		t.rttvar = rtt / 2
	} else {
		t.rttvar = uint32((1-TYPHOON_BETA)*float64(t.rttvar) + TYPHOON_BETA*math.Abs(float64(t.srtt-rtt)))
		t.srtt = uint32((1-TYPHOON_ALPHA)*float64(t.srtt) + TYPHOON_ALPHA*float64(rtt))
	}
}

func (t *TyphoonServer) regenerateNextIn(multiplier float64, rememberSent bool) {
	t.coreMutex.Lock()
	defer t.coreMutex.Unlock()

	maxTimeout := int(max(t.GetTimeout(), TYPHOON_MIN_NEXT_IN))
	t.previousNextIn = uint32(float64(utils.RandomInteger(maxTimeout, int(TYPHOON_MAX_NEXT_IN))) * multiplier)

	if rememberSent {
		t.previousSent = getTimestamp()
	}
}

// Basic network IO:

func (t *TyphoonServer) Read(buffer *betterbuf.Buffer, viridianDict *users.ViridianDict, peerBytes []byte, tunIP *net.IP) (*betterbuf.Buffer, *TyphoonConsistencyPart, error) {
	s, err := t.socket.Read(buffer.Slice())
	if err != nil {
		return nil, nil, fmt.Errorf("packet reading error: %v", err)
	}
	logrus.Debugf("Read %d bytes from viridian %d", s, t.peerID)

	packetNumber, nextIn, hdsk, data, err := parseTyphoonClientProtocolMessageType(t.cipher, buffer.RebufferEnd(s))
	if err != nil {
		logrus.Errorf("packet parsing error: %v", err)
		return nil, nil, nil
	}

	var consistencyPart *TyphoonConsistencyPart
	if hdsk {
		consistencyPart = &TyphoonConsistencyPart{packetNumber: *packetNumber, nextIn: *nextIn}
		logrus.Debugf("HDSK packet of length %d (next in %d) from viridian %d", data.Length(), *nextIn, t.peerID)

		if t.previousSent > 0 {
			t.updateTimeout(uint32((math.MaxUint32 + uint64(getTimestamp()-t.previousSent-t.previousNextIn)) % math.MaxUint32))
		}
	} else {
		logrus.Debugf("Data packet of length %d from viridian %d", data.Length(), t.peerID)
	}

	viridian, ok := viridianDict.Get(t.peerID, users.PROTOCOL_TYPHOON)
	if !ok {
		return nil, nil, fmt.Errorf("viridian with ID %d not found", t.peerID)
	}
	logrus.Debugf("Viridian %d found: name '%s', identifier '%s'", t.peerID, viridian.Name, viridian.Identifier)

	packetLength, packetSource, packetDestination, err := utils.ReadIPv4(data)
	if err != nil {
		logrus.Errorf("Reading packet information from viridian %d error: %v", t.peerID, err)
		return nil, nil, nil
	} else {
		copy(t.srcAddress, *packetSource)
	}
	logrus.Infof("Received %d bytes from viridian %d (src: %v, dst: %v)", packetLength, t.peerID, packetSource, packetDestination)

	newSrcIP := net.IPv4((*tunIP)[0], (*tunIP)[1], peerBytes[0], peerBytes[1])
	err = utils.UpdateIPv4(data, newSrcIP, nil)
	if err != nil {
		logrus.Errorf("Updating packet source from viridian %d error: %v", t.peerID, err)
		return nil, nil, nil
	}
	logrus.Debugf("Updated packet from viridian %d, new source: %v", t.peerID, newSrcIP)

	return data, consistencyPart, nil
}

func (t *TyphoonServer) Write(data *betterbuf.Buffer, controlChan chan uint32, viridianDict *users.ViridianDict) error {
	defer PacketPool.Put(data)

	packetLength, packetSource, packetDestination, err := utils.ReadIPv4(data)
	if err != nil {
		return fmt.Errorf("reading packet information from viridian %d error: %v", t.peerID, err)
	}
	logrus.Debugf("Forwarding packet to viridian %d: length %d, from %v, to %v", t.peerID, packetLength, *packetSource, *packetDestination)

	logrus.Infof("Sending %d bytes to viridian %d (src: %v, dst: %v)", packetLength, t.peerID, packetSource, t.srcAddress)

	viridian, ok := viridianDict.Get(t.peerID, users.PROTOCOL_TYPHOON)
	if !ok {
		return fmt.Errorf("viridian with ID %d not found", t.peerID)
	}
	logrus.Debugf("Viridian %d found: name '%s', identifier '%s'", t.peerID, viridian.Name, viridian.Identifier)

	err = utils.UpdateIPv4(data, nil, t.srcAddress)
	if err != nil {
		logrus.Errorf("Updating packet destination from viridian %d error: %v", t.peerID, err)
		return nil
	}
	logrus.Debugf("Updated packet to viridian %d, new destination: %v", t.peerID, t.srcAddress)

	var encrypted *betterbuf.Buffer
	select {
	case packetNumber, ok := <-controlChan:
		if ok {
			t.regenerateNextIn(TYPHOON_NORMAL_NEXT_IN, true)
			logrus.Debugf("Shadowriding HDSK viridian %d packet with number: %d", t.peerID, packetNumber)
			encrypted, err = buildTyphoonServerHDSKData(t.cipher, packetNumber, t.previousNextIn, data)
		} else {
			return errors.New("error receiving from control channel")
		}
	default:
		encrypted, err = buildTyphoonAnyData(t.cipher, data)
	}

	if err != nil {
		logrus.Errorf("Building data package for viridian error: %v", err)
		return nil
	}
	logrus.Debugf("Packet to viridian %d encrypted, new size: %d", t.peerID, encrypted.Length())

	s, err := t.socket.Write(encrypted.Slice())
	if err != nil {
		logrus.Errorf("Writing package for viridian error: %v", err)
		return nil
	}
	logrus.Debugf("Bytes written to viridian %d: %d", t.peerID, s)

	return nil
}

func (t *TyphoonServer) Terminate() error {
	packet, err := buildTyphoonAnyTerm(t.cipher)
	if err != nil {
		return fmt.Errorf("error building term packet: %v", err)
	}
	defer PacketPool.Put(packet)

	_, err = t.socket.Write(packet.Slice())
	if err != nil {
		return fmt.Errorf("error writing term packet: %v", err)
	}

	return nil
}

// Network IO routines:

func (t *TyphoonServer) serveRead(ctx context.Context, packetChan chan *betterbuf.Buffer, decayChan chan *TyphoonConsistencyPart, errorChan chan error) {
	bytesID := []byte{0, 0}
	binary.BigEndian.PutUint16(bytesID, t.peerID)

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
			packet, cons, err := t.Read(buffer, viridianDict, bytesID, &tunnelIP)

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

			// Packet carried HDSK part - update decay cycle
			if cons != nil {
				decayChan <- cons
			}

			// Packet didn't carry any data - continue listening
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

func (s *TyphoonServer) serveWrite(base context.Context, controlChan chan uint32, errorChan chan error) {
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
			err := s.Write(packet, controlChan, viridianDict)
			if err != nil {
				errorChan <- err
				return
			}
		}
	}
}

// Connection routines:

func (t *TyphoonServer) connectInner(cons *TyphoonConsistencyPart, decayChan chan *TyphoonConsistencyPart) (*TyphoonConsistencyPart, error) {
	logrus.Debugf("Continuing to viridian %d connection in %d milliseconds...", t.peerID, cons.nextIn)
	time.Sleep(time.Duration(cons.nextIn) * time.Millisecond)

	t.regenerateNextIn(TYPHOON_INITIAL_NEXT_IN, false)
	packet, err := buildTyphoonServerInit(t.cipher, t.peerID, cons.packetNumber, t.previousNextIn, SUCCESS_CODE)
	if err != nil {
		return nil, fmt.Errorf("error building init packet: %v", err)
	}
	defer PacketPool.Put(packet)

	for i := range int(t.maxRetries) {
		logrus.Debugf("Connection to viridian %d attempt %d...", t.peerID, i)
		_, err = t.listener.WriteTo(packet.Slice(), t.socket.RemoteAddr())
		if err != nil {
			return nil, fmt.Errorf("error writing init packet: %v", err)
		}

		select {
		case cons, ok := <-decayChan:
			if ok {
				return cons, nil
			} else {
				return nil, errors.New("error receiving from decay channel")
			}
		case <-time.After(time.Duration(t.previousNextIn+t.GetRTT()*2+t.GetTimeout()) * time.Millisecond):
			// continue connect
		}
	}

	return nil, fmt.Errorf("error connecting to viridian: %d", t.peerID)
}

func (t *TyphoonServer) decayInner(cons *TyphoonConsistencyPart, controlChan chan uint32, decayChan chan *TyphoonConsistencyPart) (*TyphoonConsistencyPart, error) {
	sleepTimeout := max(cons.nextIn-t.GetRTT(), 0)
	logrus.Debugf("Continuing to viridian %d handshake in %d milliseconds...", t.peerID, sleepTimeout)

	select {
	case cons, ok := <-decayChan:
		if ok {
			return cons, nil
		} else {
			return nil, errors.New("error receiving from decay channel")
		}
	case <-time.After(time.Duration(sleepTimeout) * time.Millisecond):
		// continue decay
	}

	for i := range int(t.maxRetries) {
		logrus.Debugf("Trying viridian %d handshake attempt %d...", t.peerID, i)
		controlChan <- cons.packetNumber

		sleepTimeout = t.GetRTT() * 2
		logrus.Debugf("Shadowriding timeout for viridian %d for %d milliseconds...", t.peerID, sleepTimeout)
		select {
		case cons, ok := <-decayChan:
			if ok {
				return cons, nil
			} else {
				return nil, errors.New("error receiving from decay channel")
			}
		case <-time.After(time.Duration(sleepTimeout) * time.Millisecond):
			// continue decay
		}

		select {
		case packetNumber, ok := <-controlChan:
			if !ok {
				return nil, errors.New("error receiving from control channel")
			}
			logrus.Debugf("Shadowriding for viridian %d was not successful, sending special HDSK message", t.peerID)

			t.regenerateNextIn(TYPHOON_NORMAL_NEXT_IN, true)
			packet, err := buildTyphoonServerHDSK(t.cipher, packetNumber, t.previousNextIn)
			if err != nil {
				return nil, fmt.Errorf("error building HDSK packet: %v", err)
			}

			_, err = t.socket.Write(packet.Slice())
			PacketPool.Put(packet)
			if err != nil {
				return nil, fmt.Errorf("error writing HDSK packet: %v", err)
			}
		default:
			// continue decay
		}

		sleepTimeout = max(t.previousNextIn+t.GetRTT()+t.GetTimeout(), 0)
		logrus.Debugf("Waiting for new handshake from viridian %d for %d milliseconds...", t.peerID, sleepTimeout)
		select {
		case cons = <-decayChan:
			return cons, nil
		case <-time.After(time.Duration(sleepTimeout) * time.Millisecond):
			// continue decay
		}
	}

	return nil, fmt.Errorf("connection to viridian timeout: %d", t.peerID)
}

func (t *TyphoonServer) controlSocket(ctx context.Context, cons *TyphoonConsistencyPart, controlChan chan uint32, decayChan chan *TyphoonConsistencyPart, errorChan chan error) {
	logrus.Debugf("Connecting to viridian %d, initial packet number: %d", t.peerID, cons.packetNumber)
	cons, err := t.connectInner(cons, decayChan)
	if err != nil {
		select {
		case <-ctx.Done():
			return
		default:
			errorChan <- fmt.Errorf("error in connect cycle: %v", err)
			return
		}
	}

	for {
		logrus.Debugf("Starting decay cycle for viridian: %d", t.peerID)
		cons, err = t.decayInner(cons, controlChan, decayChan)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				errorChan <- fmt.Errorf("error in decay cycle: %v", err)
				return
			}
		}
	}
}

// Serve entrypoint:

func (s *TyphoonServer) Serve(base context.Context, packetChan chan *betterbuf.Buffer, initPacketNumber uint32, initNextIn uint32) {
	localErrorChan := make(chan error)
	defer close(localErrorChan)
	controlChan := make(chan uint32)
	defer close(controlChan)
	decayChan := make(chan *TyphoonConsistencyPart)
	defer close(decayChan)

	ctx, cancel := context.WithCancel(base)
	defer cancel()

	cons := TyphoonConsistencyPart{packetNumber: initPacketNumber, nextIn: initNextIn}
	go s.controlSocket(ctx, &cons, controlChan, decayChan, localErrorChan)
	go s.serveRead(ctx, packetChan, decayChan, localErrorChan)
	go s.serveWrite(ctx, controlChan, localErrorChan)

	select {
	case <-base.Done():
		logrus.Infof("Read operation from peer %d canceled due to context cancellation!", s.peerID)
	case err := <-localErrorChan:
		logrus.Errorf("Interrupting connection with peer %d because of the error: %v", s.peerID, err)
	}
}
