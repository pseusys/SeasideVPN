package utils

import (
	"fmt"
	"net"
	"reflect"
)

const NONE_PORT = 0

var SPECIAL_IP_ADDRESSES = []uint16{0x0, 0x1, 0xFFFF}

func GetIPAndPortFromAddress(address net.Addr) (net.IP, uint16, error) {
	switch addr := address.(type) {
	case *net.UDPAddr:
		return addr.IP, uint16(addr.Port), nil
	case *net.TCPAddr:
		return addr.IP, uint16(addr.Port), nil
	default:
		return nil, NONE_PORT, fmt.Errorf("unknown address type: %v", reflect.TypeOf(address))
	}
}

func IsSpecialIPAddress(address uint16) bool {
	for _, special := range SPECIAL_IP_ADDRESSES {
		if address == special {
			return true
		}
	}
	return false
}
