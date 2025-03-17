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

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type PortListener struct {
	core    *PortCore
	address *net.TCPAddr
	servers map[uint16]*PortServer
}

func NewPortListener(address string, viridianDict *users.ViridianDict) (*PortListener, error) {
	core := newPortCore(PORT_DEFAULT_TIMEOUT)

	addr, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil {
		return nil, fmt.Errorf("error resolving network address: %v", err)
	}

	servers := make(map[uint16]*PortServer, viridianDict.MaxConnected())

	return &PortListener{
		core:    core,
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

func (p *PortListener) Listen(base context.Context, wg *sync.WaitGroup, packetChan chan *utils.Buffer, errorChan chan error) {
	defer wg.Done()

	wg = new(sync.WaitGroup)
	defer wg.Wait()

	listener, err := net.ListenTCP("tcp4", p.address)
	if err != nil {
		logrus.Errorf("error listening to %v: %v", p.address, err)
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
			wg.Add(1)
			logrus.Debugf("PORT connection accepted from %v!", conn.LocalAddr())
			go p.handleConnection(ctx, wg, conn, packetChan)
		case err := <-localErrorChan:
			logrus.Errorf("Error accepting PORT connection: %v", err)
			errorChan <- err
			return
		}
	}
}

func (p *PortListener) Write(packet *utils.Buffer, peerID uint16) bool {
	server, ok := p.servers[peerID]
	logrus.Debugf("PORT server will accept the packet from tunnel: %t", ok)
	if ok {
		server.inputChan <- packet
	}
	return ok
}

func (p *PortListener) returnWithErrorCode(conn *net.TCPConn, cipher *crypto.Symmetric, peerID uint16, code *ProtocolReturnCode) {
	var returnCode ProtocolReturnCode
	if code == nil {
		returnCode = UNKNOWN_ERROR
	} else {
		returnCode = *code
	}
	logrus.Debugf("Finishing viridian %d initialization with error code %d", peerID, returnCode)

	packet, err := p.core.buildServerInit(cipher, peerID, returnCode)
	defer PacketPool.Put(packet)
	if err != nil {
		logrus.Errorf("Error building viridian init response: %v", err)
		return
	}

	_, err = conn.Write(packet.Slice())
	if err != nil {
		logrus.Errorf("Error writing viridian init response: %v", err)
		return
	}
}

func (p *PortListener) handleInitMessage(peerID uint16, viridianDict *users.ViridianDict, conn *net.TCPConn) (*crypto.Symmetric, error) {
	defaultTimeout := time.Second * time.Duration(p.core.defaultTimeout)
	defer conn.SetReadDeadline(time.Time{})
	logrus.Debugf("Viridian %d connection deadline set to %v", peerID, defaultTimeout)

	buffer := PacketPool.GetFull()
	defer PacketPool.Put(buffer)
	encryptedHeaderLength := CLIENT_INIT_HEADER + crypto.AymmetricCiphertextOverhead

	header := buffer.RebufferEnd(encryptedHeaderLength)
	conn.SetReadDeadline(time.Now().Add(defaultTimeout))
	s, err := io.ReadFull(conn, header.Slice())
	if err != nil {
		return nil, fmt.Errorf("error reading viridian header: %v", err)
	}
	logrus.Debugf("Viridian %d header read: %d bytes", peerID, s)

	viridianName, key, tokenLength, tailLength, err := p.core.ParseClientInitHeader(crypto.PRIVATE_KEY, header)
	if err != nil {
		return nil, fmt.Errorf("error parsing viridian header: %v", err)
	}
	logrus.Debugf("Viridian %d header received with info: name %s, key %v", peerID, *viridianName, key)

	cipher, err := crypto.NewSymmetric(key)
	if err != nil {
		return nil, fmt.Errorf("error parsing viridian symmetric key: %v", err)
	}
	logrus.Debugf("Viridian %d cipher created", peerID)

	registrationCode := UNKNOWN_ERROR
	defer p.returnWithErrorCode(conn, cipher, peerID, &registrationCode)

	encryptedToken := buffer.Rebuffer(encryptedHeaderLength, encryptedHeaderLength+int(tokenLength))
	conn.SetReadDeadline(time.Now().Add(defaultTimeout))
	_, err = io.ReadFull(conn, encryptedToken.Slice())
	if err != nil {
		return nil, fmt.Errorf("error reading viridian token: %v", err)
	}
	logrus.Debugf("Viridian %d token read: %d bytes", peerID, encryptedToken.Length())

	decryptedToken, err := cipher.Decrypt(encryptedToken, nil)
	if err != nil {
		registrationCode = TOKEN_PARSE_ERROR
		return nil, fmt.Errorf("error decrypting viridian token for the first time: %v", err)
	}
	logrus.Debugf("Viridian %d token decrypted once: %v", peerID, decryptedToken)

	tokenBytes, err := crypto.SERVER_KEY.Decrypt(decryptedToken, nil)
	if err != nil {
		registrationCode = TOKEN_PARSE_ERROR
		return nil, fmt.Errorf("error decrypting viridian token for the second time: %v", err)
	}
	logrus.Debugf("Viridian %d token decrypted twice: %v", peerID, tokenBytes)

	token := new(generated.UserToken)
	err = proto.Unmarshal(tokenBytes.Slice(), token)
	if err != nil {
		registrationCode = TOKEN_PARSE_ERROR
		return nil, fmt.Errorf("error unmarshalling viridian token: %v", err)
	}
	logrus.Debugf("Viridian %d token parsed: name %s, identifier %s", peerID, token.Name, token.Identifier)

	n, err := io.CopyN(io.Discard, conn, int64(tailLength))
	if err != nil {
		return nil, fmt.Errorf("error reading viridian tail: %v", err)
	}
	logrus.Debugf("Viridian %d tail read: %d bytes", peerID, n)

	err = viridianDict.Add(peerID, viridianName, token, users.PROTOCOL_PORT)
	if err != nil {
		registrationCode = REGISTRATION_ERROR
		return nil, fmt.Errorf("error registering viridian: %v", err)
	}
	logrus.Debugf("Viridian %d added to viridian dictionary", peerID)

	registrationCode = SUCCESS_CODE
	return cipher, nil
}

func (p *PortListener) handleConnection(base context.Context, wg *sync.WaitGroup, conn *net.TCPConn, packetChan chan *utils.Buffer) {
	defer wg.Done()
	defer conn.Close()

	err := p.core.configureSocket(conn)
	if err != nil {
		logrus.Errorf("Error configuring socket: %v", err)
		return
	}
	logrus.Debugf("Connection socket configured for %v", conn.LocalAddr())

	peerIP, peerID, err := utils.GetIPAndPortFromAddress(conn.LocalAddr())
	if err != nil {
		logrus.Errorf("Error resolving viridian port number: %v", err)
		return
	}
	logrus.Debugf("Connection peer ID established for %v: %d", conn.LocalAddr(), peerID)

	viridianDict, ok := users.FromContext(base)
	if !ok {
		logrus.Errorf("viridian dictionary not found in context: %v", base)
		return
	}

	cipher, err := p.handleInitMessage(peerID, viridianDict, conn)
	if err != nil {
		logrus.Errorf("Error handling viridian init message: %v", err)
		return
	}
	defer viridianDict.Delete(peerID, false)
	logrus.Debugf("Viridian %d initialized", peerID)

	p.servers[peerID] = NewPortServer(cipher, peerID, peerIP, conn)
	defer delete(p.servers, peerID)
	logrus.Debugf("Viridian %d server created", peerID)

	defer p.servers[peerID].Terminate()
	p.servers[peerID].Serve(base, packetChan)
}
