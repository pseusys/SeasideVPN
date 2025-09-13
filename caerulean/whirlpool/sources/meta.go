package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"main/protocol"
	"main/tunnel"
	"main/users"
	"main/utils"
	"sync"

	"github.com/pseusys/betterbuf"
	"github.com/sirupsen/logrus"
)

type MetaServer struct {
	apiServer *APIServer

	portServer    *protocol.PortListener
	typhoonServer *protocol.TyphoonListener

	wg *sync.WaitGroup
}

// Start the metaserver.
// Accept context that will be used as base context.
// Return pointer to metaserver object.
func NewMetaServer(viridianDict *users.ViridianDict, tunnelConfig *tunnel.TunnelConfig) (*MetaServer, error) {
	intIP := utils.GetEnv("SEASIDE_ADDRESS", tunnelConfig.Default.IP.String())
	apiPort := uint16(utils.GetIntEnv("SEASIDE_API_PORT", tunnel.DEFAULT_API_PORT, 16))
	portPort := uint16(utils.GetIntEnv("SEASIDE_PORT_PORT", tunnel.DEFAULT_PORT_PORT, 16))
	typhoonPort := uint16(utils.GetIntEnv("SEASIDE_TYPHOON_PORT", tunnel.DEFAULT_TYPHOON_PORT, 16))

	if portPort == 0 && typhoonPort == 0 {
		return nil, errors.New("both protocols (TYPHOON and PORT) are disabled, whirlpool is just not sure what to do now")
	}

	apiAddress := fmt.Sprintf("%s:%d", intIP, apiPort)
	apiServer, err := NewAPIServer(apiAddress, portPort, typhoonPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create a gRPC API server: %v", err)
	}

	var portListener *protocol.PortListener
	if portPort != 0 {
		portAddress := fmt.Sprintf("%s:%d", intIP, portPort)
		portListener, err = protocol.NewPortListener(portAddress, viridianDict)
		if err != nil {
			return nil, fmt.Errorf("failed to create a PORT server: %v", err)
		}
	}

	var typhoonListener *protocol.TyphoonListener
	if typhoonPort != 0 {
		typhoonAddress := fmt.Sprintf("%s:%d", intIP, typhoonPort)
		typhoonListener, err = protocol.NewTyphoonListener(typhoonAddress, viridianDict)
		if err != nil {
			return nil, fmt.Errorf("failed to create a TYPHOON server: %v", err)
		}
	}

	return &MetaServer{
		apiServer:     apiServer,
		portServer:    portListener,
		typhoonServer: typhoonListener,
		wg:            nil,
	}, nil
}

func (server *MetaServer) startTunnelRead(ctx context.Context, tunnelConfig *tunnel.TunnelConfig, errorChan chan error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buffer := protocol.PacketPool.GetFull()
			s, err := tunnelConfig.Tunnel.Read(buffer.Slice())

			if err != nil {
				protocol.PacketPool.Put(buffer)
				select {
				case <-ctx.Done():
					return
				default:
					errorChan <- err
					return
				}
			} else if s == 0 {
				protocol.PacketPool.Put(buffer)
				continue
			} else {
				logrus.Debugf("Read %d bytes from tunnel", s)
			}
			buffer = buffer.RebufferEnd(s)

			packetLength, packetSource, packetDestination, err := utils.ReadIPv4(buffer)
			if err != nil {
				protocol.PacketPool.Put(buffer)
				logrus.Errorf("Error parsing tunnel packet: %v", err)
				continue
			} else {
				logrus.Debugf("Parsed packet from tunnel: length %d, from %v, to %v", packetLength, *packetSource, *packetDestination)
			}

			viridianID := binary.BigEndian.Uint16([]byte{(*packetDestination)[2], (*packetDestination)[3]})
			logrus.Debugf("Identified packet from tunnel, it belongs to viridian %d", viridianID)

			packetWritten := false
			if server.portServer != nil && !packetWritten {
				packetWritten = packetWritten || server.portServer.Write(buffer, viridianID)
			}
			if server.typhoonServer != nil && !packetWritten {
				packetWritten = packetWritten || server.typhoonServer.Write(buffer, viridianID)
			}

			if !packetWritten {
				logrus.Errorf("Error sending tunnel packet, viridian %d not found!", viridianID)
				protocol.PacketPool.Put(buffer)
			}
		}
	}
}

func (server *MetaServer) startTunnelWrite(ctx context.Context, tunnelConfig *tunnel.TunnelConfig, packetChan chan *betterbuf.Buffer) {
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-packetChan:
			s, err := tunnelConfig.Tunnel.Write(packet.Slice())
			protocol.PacketPool.Put(packet)
			if err != nil {
				logrus.Errorf("Error writing to tunnel (%d bytes written): %v", s, err)
			} else if s == 0 {
				logrus.Error("Written an empty packet to the tunnel")
			} else {
				logrus.Debugf("Written %d bytes to the tunnel", s)
			}
		}
	}
}

func (server *MetaServer) Start(base context.Context, errorChan chan error) {
	server.wg = new(sync.WaitGroup)

	server.wg.Add(1)
	defer server.wg.Done()

	tunnelConfig, ok := tunnel.FromContext(base)
	if !ok {
		errorChan <- fmt.Errorf("tunnel config not found in context: %v", base)
		return
	}

	localPacketChan := make(chan *betterbuf.Buffer, protocol.OUTPUT_CHANNEL_POOL_BUFFER)
	defer close(localPacketChan)
	localErrorChan := make(chan error)
	defer close(localErrorChan)

	ctx, cancel := context.WithCancel(base)
	defer cancel()
	go server.startTunnelRead(ctx, tunnelConfig, localErrorChan)
	go server.startTunnelWrite(ctx, tunnelConfig, localPacketChan)

	server.wg.Add(1)
	go server.apiServer.Start(ctx, server.wg, localErrorChan)

	if server.portServer != nil {
		server.wg.Add(1)
		go server.portServer.Listen(ctx, server.wg, localPacketChan, localErrorChan)
	}

	if server.typhoonServer != nil {
		server.wg.Add(1)
		go server.typhoonServer.Listen(ctx, server.wg, localPacketChan, localErrorChan)
	}

	select {
	case <-ctx.Done():
		return
	case err := <-localErrorChan:
		errorChan <- fmt.Errorf("error serving: %v", err)
	}
}

func (server *MetaServer) Stop() error {
	if server.wg == nil {
		return errors.New("MetaServer 'close' was called before 'start'")
	}

	server.apiServer.Stop()
	server.wg.Wait()

	return nil
}
