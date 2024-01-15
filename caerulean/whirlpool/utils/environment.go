package utils

import (
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
)

func GetEnv(key string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	} else {
		logrus.Fatalf("Error reading env var: %s", key)
		return ""
	}
}

func GetIntEnv(key string) int {
	if value, ok := os.LookupEnv(key); ok {
		number, err := strconv.Atoi(value)
		if err == nil {
			return number
		} else {
			logrus.Fatalf("Error converting env var: %s", key)
			return -1
		}
	} else {
		logrus.Fatalf("Error reading env var: %s", key)
		return -1
	}
}
