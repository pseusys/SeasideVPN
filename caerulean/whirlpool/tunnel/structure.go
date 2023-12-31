package tunnel

import (
	"bytes"
	"fmt"
	"net"
	"sync"

	"github.com/songgao/water"
)

// TODO: load from env
const TUNNEL_IP = "192.168.0.87/16"

type TunnelConfig struct {
	mutex   sync.Mutex
	Tunnel  *water.Interface
	IP      net.IP
	Network *net.IPNet
	buffer  bytes.Buffer
}

func Preserve() *TunnelConfig {
	return &TunnelConfig{}
}

func (conf *TunnelConfig) Open(tunIP, intIP, extIP string, seaPort, netPort, ctrlPort int) (err error) {
	conf.mutex.Lock()

	conf.IP, conf.Network, err = net.ParseCIDR(tunIP)
	if err != nil {
		return fmt.Errorf("error parsing tunnel network address (%s): %v", tunIP, err)
	}

	conf.Tunnel, err = water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return fmt.Errorf("error allocating TUN interface: %v", err)
	}

	err = openInterface(conf)
	if err != nil {
		return fmt.Errorf("error creating tunnel interface: %v", err)
	}

	err = openForwarding(intIP, extIP, conf.Tunnel.Name(), seaPort, netPort, ctrlPort)
	if err != nil {
		return fmt.Errorf("error creating firewall rules: %v", err)
	}

	conf.mutex.Unlock()
	return nil
}

func (conf *TunnelConfig) Close() {
	conf.mutex.Lock()
	closeForwarding()
	closeInterface(conf)
	conf.Tunnel.Close()
	conf.mutex.Unlock()
}
