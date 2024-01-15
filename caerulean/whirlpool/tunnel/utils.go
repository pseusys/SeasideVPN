package tunnel

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

func runCommand(cmd string, args ...string) string {
	command := exec.Command(cmd, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		logrus.Infof("Command %s output: %s", cmd, output)
		logrus.Fatalf("Error running command: %v", err)
	}
	return string(output)
}

func findInterfaceByIP(address string) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("error resolving network addresses: %v", err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			logrus.Warnf("Error parsing interface IP addresses: %s", iface.Name)
			continue
		}

		for _, addr := range addrs {
			if strings.HasPrefix(addr.String(), address) {
				return iface.Name, nil
			}
		}
	}

	return "", errors.New("error finding suitable interface")
}
