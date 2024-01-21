package tunnel

import (
	"bytes"
	"fmt"
	"net"
	"sync"

	"github.com/songgao/water"
)

const TUNNEL_IP = "172.16.0.1/12"

type TunnelConfig struct {
	mutex   sync.Mutex
	Tunnel  *water.Interface
	IP      net.IP
	Network *net.IPNet
	buffer  bytes.Buffer
}

func Preserve() *TunnelConfig {
	conf := TunnelConfig{}
	conf.mutex.Lock()
	conf.storeForwarding()
	conf.mutex.Unlock()
	return &conf
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

	err = conf.openInterface(extIP)
	if err != nil {
		return fmt.Errorf("error creating tunnel interface: %v", err)
	}

	err = conf.openForwarding(intIP, extIP, seaPort, netPort, ctrlPort)
	if err != nil {
		return fmt.Errorf("error creating firewall rules: %v", err)
	}

	conf.mutex.Unlock()
	return nil
}

func (conf *TunnelConfig) Close() {
	conf.mutex.Lock()
	conf.closeForwarding()
	conf.closeInterface()
	conf.Tunnel.Close()
	conf.mutex.Unlock()
}
