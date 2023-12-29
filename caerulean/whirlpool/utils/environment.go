package utils

import (
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
)

func GetEnv(key string, def *string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	} else if def != nil {
		return *def
	}
	logrus.Fatalf("env var '%s' undefined", key)
	return ""
}

func GetIntEnv(key string, def *int) int {
	if value, ok := os.LookupEnv(key); ok {
		number, err := strconv.Atoi(value)
		if err == nil {
			return number
		}
		logrus.Fatalf("env var '%s' not converted", key)
	} else if def != nil {
		return *def
	}
	logrus.Fatalf("env var '%s' undefined", key)
	return -1
}
