package protocol

import (
	"context"
	"fmt"
	"main/crypto"
	"main/generated"
	"main/users"
	"main/utils"
	"net"
	"sync"
	"time"

	"github.com/pseusys/betterbuf"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type UDPConnWithPacket struct {
	addr *net.UDPAddr
	buff *betterbuf.Buffer
}

type TyphoonListener struct {
	address *net.UDPAddr
	servers map[uint16]*TyphoonServer
}

func NewTyphoonListener(address string, viridianDict *users.ViridianDict) (*TyphoonListener, error) {
	addr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return nil, fmt.Errorf("error resolving network address: %v", err)
	}

	servers := make(map[uint16]*TyphoonServer, viridianDict.MaxConnected())

	return &TyphoonListener{
		address: addr,
		servers: servers,
	}, nil
}

func (t *TyphoonListener) listenInternal(ctx context.Context, listener *net.UDPConn, connChan chan *UDPConnWithPacket, errorChan chan error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buffer := PacketPool.GetFull()
			n, address, err := listener.ReadFromUDP(buffer.Slice())

			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					errorChan <- err
					return
				}
			}

			select {
			case <-ctx.Done():
				return
			default:
				connChan <- &UDPConnWithPacket{
					addr: address,
					buff: buffer.RebufferEnd(n),
				}
			}
		}
	}
}

func (t *TyphoonListener) Listen(base context.Context, wg *sync.WaitGroup, packetChan chan *betterbuf.Buffer, errorChan chan error) {
	defer wg.Done()

	innerWG := new(sync.WaitGroup)
	defer innerWG.Wait()

	listener, err := net.ListenUDP("udp4", t.address)
	if err != nil {
		logrus.Errorf("Error listening to %v: %v", t.address, err)
		return
	}
	defer listener.Close()

	localErrorChan := make(chan error)
	defer close(localErrorChan)
	localConnChan := make(chan *UDPConnWithPacket)
	defer close(localConnChan)

	ctx, cancel := context.WithCancel(base)
	defer cancel()
	go t.listenInternal(ctx, listener, localConnChan, localErrorChan)

	logrus.Infof("TYPHOON listener started at %v!", t.address)
	for {
		select {
		case <-ctx.Done():
			return
		case cwp := <-localConnChan:
			innerWG.Add(1)
			logrus.Debugf("TYPHOON connection accepted from %v!", cwp.addr)
			go t.handleConnection(ctx, innerWG, listener, cwp, packetChan)
		case err := <-localErrorChan:
			logrus.Errorf("Error accepting TYPHOON connection: %v", err)
			errorChan <- err
			return
		}
	}
}

func (t *TyphoonListener) Write(packet *betterbuf.Buffer, peerID uint16) bool {
	server, ok := t.servers[peerID]
	logrus.Debugf("TYPHOON server will accept the packet from tunnel: %t", ok)
	if ok {
		server.inputChan <- packet
	}
	return ok
}

func (t *TyphoonListener) returnWithErrorCode(conn *net.UDPConn, addr *net.UDPAddr, cipher *crypto.Symmetric, packetNumber uint32, code *ProtocolReturnCode) {
	var returnCode ProtocolReturnCode
	if code == nil {
		returnCode = UNKNOWN_ERROR
	} else {
		returnCode = *code
	}
	logrus.Debugf("Finishing viridian at %v initialization with error code %d", *addr, returnCode)

	packet, err := buildTyphoonServerInit(cipher, 0, packetNumber, TYPHOON_NEVER_NEXT_IN, returnCode)
	defer PacketPool.Put(packet)
	if err != nil {
		logrus.Errorf("Error building viridian init response: %v", err)
		return
	}

	_, err = conn.WriteToUDP(packet.Slice(), addr)
	if err != nil {
		logrus.Errorf("Error writing viridian init response: %v", err)
		return
	}
}

func createTyphoonViridianHandle(address *net.UDPAddr) (any, uint16, error) {
	conn, err := net.DialUDP("udp4", nil, address)
	if err != nil {
		return nil, 0, fmt.Errorf("error allocating port: %v", err)
	}
	logrus.Debugf("Connection peer ID established for %v - %v", conn.LocalAddr(), conn.RemoteAddr())

	_, peerID, err := utils.GetIPAndPortFromAddress(conn.LocalAddr())
	if err != nil {
		conn.Close()
		return nil, 0, fmt.Errorf("error retrieving port information: %v", err)
	}
	logrus.Debugf("Connection peer ID determined for %v: %d", conn.LocalAddr(), peerID)

	return conn, peerID, nil
}

func (t *TyphoonListener) handleInitMessage(viridianDict *users.ViridianDict, address *net.UDPAddr, buffer *betterbuf.Buffer) (*net.UDPConn, *net.IP, *uint16, *crypto.Symmetric, ProtocolReturnCode, *uint32, *uint32, error) {
	peerIP, peerPort, err := utils.GetIPAndPortFromAddress(address)
	if err != nil {
		return nil, nil, nil, nil, UNKNOWN_ERROR, nil, nil, fmt.Errorf("error resolving viridian port number: %v", err)
	}
	logrus.Debugf("Viridian %v:%v packet received: %d bytes", peerIP, peerPort, buffer.Length())

	viridianName, key, encryptedToken, packetNumber, nextIn, err := parseTyphoonClientInit(crypto.PRIVATE_KEY, buffer)
	if err != nil {
		return nil, nil, nil, nil, UNKNOWN_ERROR, nil, nil, fmt.Errorf("error parsing viridian packet: %v", err)
	}
	logrus.Debugf("Viridian %v:%v packet received with info: name %s, symmetric key, packet number %d, next in %d, encrypted token %v", peerIP, peerPort, *viridianName, *packetNumber, *nextIn, encryptedToken)

	cipher, err := crypto.NewSymmetric(key)
	if err != nil {
		return nil, nil, nil, nil, UNKNOWN_ERROR, packetNumber, nextIn, fmt.Errorf("error parsing viridian symmetric key: %v", err)
	}
	logrus.Debugf("Viridian %v:%v cipher created", peerIP, peerPort)

	tokenBytes, err := crypto.SERVER_KEY.Decrypt(encryptedToken, nil)
	if err != nil {
		return nil, nil, nil, cipher, TOKEN_PARSE_ERROR, packetNumber, nextIn, fmt.Errorf("error decrypting viridian token: %v", err)
	}
	logrus.Debugf("Viridian %v:%v token decrypted: %v", peerIP, peerPort, tokenBytes)

	token := new(generated.ClientToken)
	err = proto.Unmarshal(tokenBytes.Slice(), token)
	if err != nil {
		return nil, nil, nil, cipher, TOKEN_PARSE_ERROR, packetNumber, nextIn, fmt.Errorf("error unmarshaling viridian token: %v", err)
	}
	logrus.Debugf("Viridian %v:%v token parsed: name %s, identifier %s", peerIP, peerPort, token.Name, token.Identifier)

	handle, peerID, err := viridianDict.Add(func() (any, uint16, error) { return createTyphoonViridianHandle(address) }, viridianName, token, users.PROTOCOL_TYPHOON)
	if err != nil {
		return nil, nil, nil, cipher, REGISTRATION_ERROR, packetNumber, nextIn, fmt.Errorf("error registering viridian: %v", err)
	}
	logrus.Debugf("Viridian %d added to viridian dictionary", peerID)

	conn, ok := handle.(*net.UDPConn)
	if !ok {
		return nil, nil, nil, cipher, REGISTRATION_ERROR, packetNumber, nextIn, fmt.Errorf("error casting user connection: %v", handle)
	}
	logrus.Debugf("Connection peer ID established for %v:%v: %d", peerIP, peerPort, peerID)

	connIP, _, err := utils.GetIPAndPortFromAddress(conn.RemoteAddr())
	if err != nil {
		conn.Close()
		return nil, nil, nil, cipher, REGISTRATION_ERROR, packetNumber, nextIn, fmt.Errorf("error retrieving IP information: %v", err)
	}
	logrus.Debugf("Connection peer initial source IP determined for %v: %v", conn.RemoteAddr(), connIP)

	return conn, &connIP, &peerID, cipher, SUCCESS_CODE, packetNumber, nextIn, nil
}

func (t *TyphoonListener) handleConnection(base context.Context, wg *sync.WaitGroup, listener *net.UDPConn, cwp *UDPConnWithPacket, packetChan chan *betterbuf.Buffer) {
	defer wg.Done()

	viridianDict, ok := users.FromContext(base)
	if !ok {
		logrus.Errorf("viridian dictionary not found in context: %v", base)
		return
	}

	conn, peerIP, peerID, cipher, code, packetNumber, nextIn, err := t.handleInitMessage(viridianDict, cwp.addr, cwp.buff)
	if err != nil {
		logrus.Errorf("Error handling viridian init message (%v): %v", code, err)
		if code != UNKNOWN_ERROR {
			time.Sleep(time.Duration(*nextIn) * time.Millisecond)
			t.returnWithErrorCode(listener, cwp.addr, cipher, *packetNumber, &code)
		}
		return
	}
	defer conn.Close()
	defer viridianDict.Delete(*peerID, false)
	logrus.Debugf("Viridian %d initialized", *peerID)

	t.servers[*peerID] = NewTyphoonServer(cipher, *peerID, *peerIP, listener, conn)
	defer delete(t.servers, *peerID)
	logrus.Debugf("Viridian %d server created", *peerID)

	defer t.servers[*peerID].Terminate()
	t.servers[*peerID].Serve(base, packetChan, *packetNumber, *nextIn)
}
