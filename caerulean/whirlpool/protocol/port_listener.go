package protocol

import (
	"context"
	"fmt"
	"io"
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

type PortListener struct {
	address *net.TCPAddr
	servers map[uint16]*PortServer
}

func NewPortListener(address string, viridianDict *users.ViridianDict) (*PortListener, error) {
	addr, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil {
		return nil, fmt.Errorf("error resolving network address: %v", err)
	}

	servers := make(map[uint16]*PortServer, viridianDict.MaxConnected())

	return &PortListener{
		address: addr,
		servers: servers,
	}, nil
}

func (p *PortListener) listenInternal(ctx context.Context, listener *net.TCPListener, connChan chan *net.TCPConn, errorChan chan error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := listener.AcceptTCP()

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
				connChan <- conn
			}
		}
	}
}

func (p *PortListener) Listen(base context.Context, wg *sync.WaitGroup, packetChan chan *betterbuf.Buffer, errorChan chan error) {
	defer wg.Done()

	innerWG := new(sync.WaitGroup)
	defer innerWG.Wait()

	listener, err := net.ListenTCP("tcp4", p.address)
	if err != nil {
		logrus.Errorf("Error listening to %v: %v", p.address, err)
		return
	}
	defer listener.Close()

	localErrorChan := make(chan error)
	defer close(localErrorChan)
	localConnChan := make(chan *net.TCPConn)
	defer close(localConnChan)

	ctx, cancel := context.WithCancel(base)
	defer cancel()
	go p.listenInternal(ctx, listener, localConnChan, localErrorChan)

	logrus.Infof("PORT listener started at %v!", p.address)
	for {
		select {
		case <-ctx.Done():
			return
		case conn := <-localConnChan:
			innerWG.Add(1)
			logrus.Debugf("PORT connection accepted from %v!", conn.LocalAddr())
			go p.handleConnection(ctx, innerWG, conn, packetChan)
		case err := <-localErrorChan:
			logrus.Errorf("Error accepting PORT connection: %v", err)
			errorChan <- err
			return
		}
	}
}

func (p *PortListener) Write(packet *betterbuf.Buffer, peerID uint16) bool {
	server, ok := p.servers[peerID]
	logrus.Debugf("PORT server will accept the packet from tunnel: %t", ok)
	if ok {
		server.inputChan <- packet
	}
	return ok
}

func (p *PortListener) returnWithErrorCode(conn *net.TCPConn, cipher *crypto.Symmetric, peerID *uint16, code *ProtocolReturnCode) {
	var returnCode ProtocolReturnCode
	if code == nil {
		returnCode = UNKNOWN_ERROR
	} else {
		returnCode = *code
	}

	var peerPort uint16
	if peerID == nil {
		peerPort = 0
	} else {
		peerPort = *peerID
	}

	logrus.Debugf("Finishing viridian at %v initialization with error code %d", conn, returnCode)
	packet, err := buildPortServerInit(cipher, peerPort, returnCode)
	if err != nil {
		logrus.Errorf("Error building viridian init response: %v", err)
		return
	}
	defer PacketPool.Put(packet)

	_, err = conn.Write(packet.Slice())
	if err != nil {
		logrus.Errorf("Error writing viridian init response: %v", err)
		return
	}
}

func createPortViridianHandle(address *net.TCPAddr) (any, uint16, error) {
	addr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%v:%d", address.IP, 0))
	if err != nil {
		return nil, 0, fmt.Errorf("error resolving connection address: %v", err)
	}
	logrus.Debugf("Connection address resolved: %v", addr)

	listener, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		return nil, 0, fmt.Errorf("error listening to %v: %v", address, err)
	}
	logrus.Debugf("New socket for peer established: %v", listener.Addr())

	_, peerID, err := utils.GetIPAndPortFromAddress(listener.Addr())
	if err != nil {
		listener.Close()
		return nil, 0, fmt.Errorf("error resolving viridian port number: %v", err)
	}
	logrus.Debugf("Connection peer ID determined for %v: %d", listener.Addr(), peerID)

	return listener, peerID, nil
}

func (p *PortListener) handleInitMessage(viridianDict *users.ViridianDict, conn *net.TCPConn) (*net.TCPListener, *net.IP, *uint16, *crypto.Symmetric, error) {
	listenIP, listenPort, err := utils.GetIPAndPortFromAddress(conn.RemoteAddr())
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("error resolving viridian port number: %v", err)
	}
	logrus.Debugf("Viridian %v:%v packet resolved", listenIP, listenPort)

	defaultTimeout := time.Second * time.Duration(PORT_TIMEOUT)
	defer conn.SetReadDeadline(time.Time{})
	logrus.Debugf("Viridian %v:%v connection deadline set to %v", listenIP, listenPort, defaultTimeout)

	buffer := PacketPool.GetFull()
	defer PacketPool.Put(buffer)
	encryptedHeaderLength := PORT_CLIENT_INIT_HEADER + crypto.AsymmetricCiphertextOverhead

	header := buffer.RebufferEnd(encryptedHeaderLength)
	conn.SetReadDeadline(time.Now().Add(defaultTimeout))
	s, err := io.ReadFull(conn, header.Slice())
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("error reading viridian header: %v", err)
	}
	logrus.Debugf("Viridian %v:%v header read: %d bytes", listenIP, listenPort, s)

	viridianName, key, tokenLength, tailLength, err := parsePortClientInitHeader(crypto.PRIVATE_KEY, header)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("error parsing viridian header: %v", err)
	}
	logrus.Debugf("Viridian %v:%v header received with info: name %s, key %v", listenIP, listenPort, *viridianName, key)

	cipher, err := crypto.NewSymmetric(key)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("error parsing viridian symmetric key: %v", err)
	}
	logrus.Debugf("Viridian %v:%v cipher created", listenIP, listenPort)

	peerID := uint16(0)
	registrationCode := UNKNOWN_ERROR
	defer p.returnWithErrorCode(conn, cipher, &peerID, &registrationCode)

	encryptedToken := buffer.Rebuffer(encryptedHeaderLength, encryptedHeaderLength+int(tokenLength))
	conn.SetReadDeadline(time.Now().Add(defaultTimeout))
	_, err = io.ReadFull(conn, encryptedToken.Slice())
	if err != nil {
		return nil, nil, nil, cipher, fmt.Errorf("error reading viridian token: %v", err)
	}
	logrus.Debugf("Viridian %v:%v token read: %d bytes", listenIP, listenPort, encryptedToken.Length())

	decryptedToken, err := cipher.Decrypt(encryptedToken, nil)
	if err != nil {
		registrationCode = TOKEN_PARSE_ERROR
		return nil, nil, nil, cipher, fmt.Errorf("error decrypting viridian token for the first time: %v", err)
	}
	logrus.Debugf("Viridian %v:%v token decrypted once: %v", listenIP, listenPort, decryptedToken)

	tokenBytes, err := crypto.SERVER_KEY.Decrypt(decryptedToken, nil)
	if err != nil {
		registrationCode = TOKEN_PARSE_ERROR
		return nil, nil, nil, cipher, fmt.Errorf("error decrypting viridian token for the second time: %v", err)
	}
	logrus.Debugf("Viridian %v:%v token decrypted twice: %v", listenIP, listenPort, tokenBytes)

	token := new(generated.UserToken)
	err = proto.Unmarshal(tokenBytes.Slice(), token)
	if err != nil {
		registrationCode = TOKEN_PARSE_ERROR
		return nil, nil, nil, cipher, fmt.Errorf("error unmarshaling viridian token: %v", err)
	}
	logrus.Debugf("Viridian %v:%v token parsed: name %s, identifier %s", listenIP, listenPort, token.Name, token.Identifier)

	n, err := io.CopyN(io.Discard, conn, int64(tailLength))
	if err != nil {
		return nil, nil, nil, cipher, fmt.Errorf("error reading viridian tail: %v", err)
	}
	logrus.Debugf("Viridian %v:%v tail read: %d bytes", listenIP, listenPort, n)

	handle, peerID, err := viridianDict.Add(func() (any, uint16, error) { return createPortViridianHandle(p.address) }, viridianName, token, users.PROTOCOL_PORT)
	if err != nil {
		registrationCode = REGISTRATION_ERROR
		return nil, nil, nil, cipher, fmt.Errorf("error registering viridian: %v", err)
	}
	logrus.Debugf("Viridian %d added to viridian dictionary", peerID)

	listener, ok := handle.(*net.TCPListener)
	if !ok {
		registrationCode = REGISTRATION_ERROR
		return nil, nil, nil, cipher, fmt.Errorf("error casting user connection: %v", handle)
	}
	logrus.Debugf("Connection peer ID established for %v:%v: %d", listenIP, listenPort, peerID)

	registrationCode = SUCCESS_CODE
	return listener, &listenIP, &peerID, cipher, nil
}

func (p *PortListener) handleConnection(base context.Context, wg *sync.WaitGroup, listener *net.TCPConn, packetChan chan *betterbuf.Buffer) {
	defer wg.Done()

	err := configurePortSocket(listener)
	if err != nil {
		logrus.Errorf("Error initial configuring socket: %v", err)
		listener.Close()
		return
	}
	logrus.Debugf("Initial socket configured for a new connection at %v", listener.LocalAddr())

	viridianDict, ok := users.FromContext(base)
	if !ok {
		logrus.Errorf("viridian dictionary not found in context: %v", base)
		listener.Close()
		return
	}

	conn, peerIP, peerID, cipher, err := p.handleInitMessage(viridianDict, listener)
	if err != nil {
		logrus.Errorf("Error handling viridian init message: %v", err)
		listener.Close()
		return
	}
	defer viridianDict.Delete(*peerID, false)

	socket, err := conn.AcceptTCP()
	listener.Close()
	conn.Close()
	if err != nil {
		logrus.Errorf("Error accepting connection socket: %v", err)
		return
	}
	defer socket.Close()
	logrus.Debugf("Initial socket accepted for %v", socket.LocalAddr())

	err = configurePortSocket(socket)
	if err != nil {
		logrus.Errorf("Error configuring connection socket: %v", err)
		return
	}
	logrus.Debugf("Initial socket configured for %v", listener.LocalAddr())

	logrus.Debugf("Viridian %d initialized", *peerID)

	p.servers[*peerID] = NewPortServer(cipher, *peerID, *peerIP, socket)
	defer delete(p.servers, *peerID)
	logrus.Debugf("Viridian %d server created", *peerID)

	defer p.servers[*peerID].Terminate()
	p.servers[*peerID].Serve(base, packetChan)
}
