package utils

import (
	"fmt"
	"net"
	"reflect"
)

// None (invalid) port number
const NONE_PORT = 0

// List of special IP addresses.
// These addresses are not valid in any network with 16 prefix length.
// Includes following IP addresses:
// - *.*.0.0 (network address)
// - *.*.0.1 (gateway address)
// - *.*.255.255 (broadcast address)
var SPECIAL_IP_ADDRESSES = []uint16{0x0000, 0x0001, 0xFFFF}

// Get IP and port address from net.Addr object.
// Accept address object.
// Return net.IP object, port number and nil if successful, nil, NONE_PORT and error otherwise.
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

// Check if IP address is special.
// Special IP addresses are listed in SPECIAL_IP_ADDRESSES array.
// Accept integer that represents 2 last bytes of the IP address to check.
// Returns True if IP address is special, False otherwise.
func IsSpecialIPAddress(address uint16) bool {
	for _, special := range SPECIAL_IP_ADDRESSES {
		if address == special {
			return true
		}
	}
	return false
}
