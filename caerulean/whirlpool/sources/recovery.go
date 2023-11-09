package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

func WriteRecoveryFile() {
	int_ip := fmt.Sprintf("Internal IP: %s\n", *iIP)
	ext_ip := fmt.Sprintf("External IP: %s\n", *eIP)
	sea_port := fmt.Sprintf("Seaside port: %d\n", *port)
	ctrl_port := fmt.Sprintf("Control port: %d\n", *control)
	net_port := fmt.Sprintf("Network port: %d\n", *network)
	result := []byte(int_ip + ext_ip + sea_port + ctrl_port + net_port)

	executable, err := os.Executable()
	if err != nil {
		logrus.Panicln("error resolving executable file path", err)
	}

	path := path.Join(filepath.Dir(executable), "recovery.txt")
	logrus.Println(path)
	err = os.WriteFile(path, result, 0644)
	if err != nil {
		logrus.Panicln("error writing recovery file", err)
	}
}
