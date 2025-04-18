package crypto

import (
	"encoding/base64"
	"main/utils"

	"github.com/pseusys/betterbuf"
	"github.com/sirupsen/logrus"
)

var (
	SERVER_KEY  *Symmetric
	PRIVATE_KEY *Asymmetric
)

func init() {
	serverKeyBytes, err := base64.StdEncoding.DecodeString(utils.RequireEnv("SEASIDE_SERVER_KEY"))
	if err != nil {
		logrus.Fatalf("Error parsing server key from environment variable: %v", err)
	}

	SERVER_KEY, err = NewSymmetric(betterbuf.NewBufferFromSlice(serverKeyBytes))
	if err != nil {
		logrus.Fatalf("error creating server symmetric cipher: %v", err)
	}

	privateKeyBytes, err := base64.StdEncoding.DecodeString(utils.RequireEnv("SEASIDE_PRIVATE_KEY"))
	if err != nil {
		logrus.Fatalf("Error parsing private key from environment variable: %v", err)
	}

	PRIVATE_KEY, err = NewAsymmetric(betterbuf.NewBufferFromSlice(privateKeyBytes), true)
	if err != nil {
		logrus.Fatalf("error creating server symmetric cipher: %v", err)
	}
}
