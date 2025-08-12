package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var DEFAULT_IP_ADDRESS = []byte{0, 0, 0, 0}

// Execute console command.
// Accept executable name and vararg command arguments.
// Return stdout and stderr as a string, terminate if command execution failed.
func runCommand(cmd string, args ...string) (string, error) {
	command := exec.Command(cmd, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		logrus.Errorf("Command %s output: %s", cmd, output)
		return "", fmt.Errorf("error running command: %v", args)
	} else {
		return string(output), nil
	}
}

func findDefaultInterface() (*net.IPNet, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("error getting route list: %v", err)
	}

	for _, route := range routes {
		if route.Dst == nil || route.Dst.IP.Equal(DEFAULT_IP_ADDRESS) {
			iface, err := net.InterfaceByIndex(route.LinkIndex)
			if err != nil {
				logrus.Warnf("Error resolving interface %d: %v", route.LinkIndex, err)
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil {
				logrus.Warnf("Error parsing interface IP addresses %s, %v", iface.Name, err)
				continue
			}

			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if ok {
					return ipNet, nil
				}
			}
		}
	}

	return nil, errors.New("default route not found")
}

// Find network interface by IP address.
// Accept IP address as a string.
// Return network interface pointer and nil if interface was found, otherwise nil and error.
func findInterfaceByIP(address string) (*net.Interface, error) {
	// Receive network interface list
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("error resolving network addresses: %v", err)
	}

	// Iterate network interfaces
	for _, iface := range ifaces {
		// For each interface, find assigned IP addresses
		addrs, err := iface.Addrs()
		if err != nil {
			logrus.Warnf("Error parsing interface IP addresses: %s", iface.Name)
			continue
		}

		// If IP address matches given, return interface pointer
		for _, addr := range addrs {
			if strings.HasPrefix(addr.String(), address) {
				return &iface, nil
			}
		}
	}

	// Return nil and error
	return nil, errors.New("error finding suitable interface")
}

// An empty type that would be stored for keeping TunnelConfig object in context.
type tunnelConfigKey struct{}

// Copy context, appending TunnelConfig to it.
// Accept context to copy and config to insert.
// Return an updated context.
func NewContext(ctx context.Context, config *TunnelConfig) context.Context {
	return context.WithValue(ctx, tunnelConfigKey{}, config)
}

// Retrieve TunnelConfig from context.
// Accept context.
// Return TunnelConfig and True if successful, nil and False otherwise.
func FromContext(ctx context.Context) (*TunnelConfig, bool) {
	config, ok := ctx.Value(tunnelConfigKey{}).(*TunnelConfig)
	return config, ok
}

// Convert string to null-terminated byte sequence.
// Accept string to convert.
// Return bytes.
func NullTerminatedString(str string) []byte {
	return append([]byte(str), 0)
}
