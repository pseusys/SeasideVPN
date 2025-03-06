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

	"github.com/sirupsen/logrus"
)

type MetaServer struct {
	apiServer *APIServer

	portServer *protocol.PortListener

	wg *sync.WaitGroup
}

// Start the metaserver.
// Accept context that will be used as base context.
// Return pointer to metaserver object.
func NewMetaServer(viridianDict *users.ViridianDict, tunnelConfig *tunnel.TunnelConfig) (*MetaServer, error) {
	intIP := utils.GetEnv("SEASIDE_ADDRESS", tunnelConfig.Default.IP.String())
	apiPort := uint16(utils.GetIntEnv("SEASIDE_API_PORT", tunnel.DEFAULT_API_PORT, 16))
	portPort := int32(utils.GetIntEnv("SEASIDE_PORT_PORT", tunnel.DEFAULT_PORT_PORT, 32))
	typhoonPort := int32(utils.GetIntEnv("SEASIDE_TYPHOON_PORT", tunnel.DEFAULT_TYPHOON_PORT, 32))

	apiAddress := fmt.Sprintf("%s:%d", intIP, apiPort)
	apiServer, err := NewAPIServer(apiAddress, portPort, typhoonPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create a gRPC API server: %v", err)
	}

	portAddress := fmt.Sprintf("%s:%d", intIP, portPort)
	portListener, err := protocol.NewPortListener(portAddress, viridianDict)
	if err != nil {
		return nil, fmt.Errorf("failed to create a PORT server: %v", err)
	}

	// TODO: create TYPHOON server AND option to disable a protocol

	return &MetaServer{
		apiServer:  apiServer,
		portServer: portListener,
		wg:         nil,
	}, nil
}

func (server *MetaServer) startTunnelRead(base context.Context, tunnelConfig *tunnel.TunnelConfig, errorChan chan error) {
	for {
		select {
		case <-base.Done():
			return
		default:
			buffer := protocol.PacketPool.Get()
			s, err := tunnelConfig.Tunnel.Read(buffer.Slice())

			if err != nil || s == 0 {
				protocol.PacketPool.Put(buffer)
				errorChan <- err
				return
			}

			_, _, packetDestination, err := utils.ReadIPv4(buffer)
			if err != nil {
				protocol.PacketPool.Put(buffer)
				logrus.Errorf("Error parsing tunnel packet: %v", err)
				continue
			}

			viridianID := binary.BigEndian.Uint16([]byte{(*packetDestination)[2], (*packetDestination)[3]})

			packetWritten := false
			packetWritten = packetWritten || server.portServer.Write(buffer, viridianID)

			if !packetWritten {
				protocol.PacketPool.Put(buffer)
				logrus.Errorf("Error sending tunnel packet: %v", err)
			}
		}
	}
}

func (server *MetaServer) startTunnelWrite(base context.Context, tunnelConfig *tunnel.TunnelConfig, packetChan chan *utils.Buffer) {
	defer server.wg.Done()

	for {
		select {
		case <-base.Done():
			return
		case packet := <-packetChan:
			s, err := tunnelConfig.Tunnel.Write(packet.Slice())
			protocol.PacketPool.Put(packet)
			if err != nil || s == 0 {
				logrus.Errorf("Error writing to tunnel (%d bytes written): %v", s, err)
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

	localPacketChan := make(chan *utils.Buffer, protocol.OUTPUT_CHANNEL_POOL_BUFFER)
	defer close(localPacketChan)
	localErrorChan := make(chan error)
	defer close(localErrorChan)

	go server.startTunnelRead(base, tunnelConfig, localErrorChan)
	go server.startTunnelWrite(base, tunnelConfig, localPacketChan)

	server.wg.Add(2)
	go server.apiServer.Start(server.wg, localErrorChan)
	go server.portServer.Listen(base, server.wg, localPacketChan, localErrorChan)

	for {
		select {
		case <-base.Done():
			return
		case err := <-localErrorChan:
			errorChan <- fmt.Errorf("error serving: %v", err)
			return
		}
	}
}

func (server *MetaServer) Stop() error {
	if server.wg == nil {
		return errors.New("MetaServer 'close' was called before 'start'")
	}

	server.portServer.Close()
	server.apiServer.Stop()
	server.wg.Wait()

	return nil
}
