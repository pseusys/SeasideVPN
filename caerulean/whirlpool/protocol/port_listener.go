package protocol

import (
	"context"
	"errors"
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
	ctx     *context.Context
	cancel  *context.CancelFunc
	wg      *sync.WaitGroup
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
		ctx:     nil,
		cancel:  nil,
		wg:      nil,
	}, nil
}

func (p *PortListener) listenInternal(base context.Context, listener *net.TCPListener, connChan chan *net.TCPConn, errorChan chan error) {
	for {
		select {
		case <-base.Done():
			return
		default:
			conn, err := listener.AcceptTCP()

			if err != nil {
				errorChan <- err
				return
			}

			select {
			case connChan <- conn:
				// The receiver is responsible for returning the buffer after usage.
			case <-base.Done():
				return
			}
		}
	}
}

func (p *PortListener) Listen(base context.Context, wg *sync.WaitGroup, packetChan chan *utils.Buffer, errorChan chan error) {
	defer wg.Done()

	ctx, cancel := context.WithCancel(base)
	p.ctx = &ctx
	p.cancel = &cancel
	p.wg = new(sync.WaitGroup)

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

	go p.listenInternal(base, listener, localConnChan, localErrorChan)

	for {
		select {
		case <-ctx.Done():
			return
		case conn := <-localConnChan:
			p.wg.Add(1)
			go p.handleConnection(ctx, conn, packetChan)
		case err := <-localErrorChan:
			logrus.Errorf("Error accepting PORT connection: %v", err)
			errorChan <- err
			return
		}
	}
}

func (p *PortListener) Write(packet *utils.Buffer, peerID uint16) bool {
	server, ok := p.servers[peerID]
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

func (p *PortListener) handleInitMessage(peerID uint16, serverKey *crypto.Symmetric, viridianDict *users.ViridianDict, conn *net.TCPConn) (*crypto.Symmetric, error) {
	defaultTimeout := time.Duration(p.core.defaultTimeout)

	encryptedHeaderLength := CLIENT_INIT_HEADER + crypto.AymmetricCiphertextOverhead
	header := PacketPool.Get().RebufferEnd(encryptedHeaderLength)
	defer PacketPool.Put(header)

	conn.SetReadDeadline(time.Now().Add(defaultTimeout))
	_, err := io.ReadFull(conn, header.Slice())
	if err != nil {
		return nil, fmt.Errorf("error reading viridian header: %v", err)
	}

	viridianName, key, tokenLength, tailLength, err := p.core.ParseClientInitHeader(crypto.PRIVATE_KEY, header)
	if err != nil {
		return nil, fmt.Errorf("error parsing viridian header: %v", err)
	}

	cipher, err := crypto.NewSymmetric(key)
	if err != nil {
		return nil, fmt.Errorf("error parsing viridian symmetric key: %v", err)
	}

	registrationCode := UNKNOWN_ERROR
	defer p.returnWithErrorCode(conn, cipher, peerID, &registrationCode)

	encryptedToken := header.Rebuffer(encryptedHeaderLength, encryptedHeaderLength+uint(tokenLength)+crypto.SymmetricCiphertextOverhead)
	conn.SetReadDeadline(time.Now().Add(defaultTimeout))
	_, err = io.ReadFull(conn, encryptedToken.Slice())
	if err != nil {
		return nil, fmt.Errorf("error reading viridian token: %v", err)
	}

	tokenBytes, err := serverKey.Decrypt(encryptedToken, nil)
	if err != nil {
		registrationCode = TOKEN_PARSE_ERROR
		return nil, fmt.Errorf("error decrypting viridian token: %v", err)
	}

	token := new(generated.UserToken)
	err = proto.Unmarshal(tokenBytes.Slice(), token)
	if err != nil {
		registrationCode = TOKEN_PARSE_ERROR
		return nil, fmt.Errorf("error unmarshalling viridian token: %v", err)
	}

	_, err = io.CopyN(io.Discard, conn, int64(tailLength))
	if err != nil {
		return nil, fmt.Errorf("error reading viridian tail: %v", err)
	}

	err = viridianDict.Add(peerID, viridianName, token, users.PROTOCOL_PORT)
	if err != nil {
		registrationCode = REGISTRATION_ERROR
		return nil, fmt.Errorf("error registering viridian: %v", err)
	}

	registrationCode = SUCCESS_CODE
	return cipher, nil
}

func (p *PortListener) handleConnection(base context.Context, conn *net.TCPConn, packetChan chan *utils.Buffer) {
	defer p.wg.Done()
	defer conn.Close()

	err := p.core.configureSocket(conn)
	if err != nil {
		logrus.Errorf("Error configuring socket: %v", err)
		return
	}

	_, peerID, err := utils.GetIPAndPortFromAddress(conn.LocalAddr())
	if err != nil {
		logrus.Errorf("Error resolving viridian port number: %v", err)
		return
	}

	viridianDict, ok := users.FromContext(base)
	if !ok {
		logrus.Errorf("viridian dictionary not found in context: %v", base)
		return
	}

	cipher, err := p.handleInitMessage(peerID, crypto.SERVER_KEY, viridianDict, conn)
	if err != nil {
		logrus.Errorf("Error handling viridian init message: %v", err)
		return
	}
	defer viridianDict.Delete(peerID, false)

	p.servers[peerID] = NewPortServer(cipher, peerID, conn)
	defer delete(p.servers, peerID)

	defer p.servers[peerID].Terminate()
	p.servers[peerID].Serve(base, packetChan)
}

func (p *PortListener) Close() error {
	if p.ctx == nil {
		return errors.New("PortListener 'close' was called before 'listen'")
	}

	(*p.cancel)()
	p.wg.Wait()
	return nil
}
