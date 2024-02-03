package tunnel

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

// Execute console command.
// Accept executable name and vararg command arguments.
// Return stdout and stderr as a string, terminate if command execution failed.
func runCommand(cmd string, args ...string) string {
	command := exec.Command(cmd, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		logrus.Infof("Command %s output: %s", cmd, output)
		logrus.Fatalf("Error running command: %v", err)
	}
	return string(output)
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
