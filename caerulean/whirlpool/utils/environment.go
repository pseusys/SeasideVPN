package utils

import (
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
)

// Get value from environment variable.
// Accept environment variable (string).
// Return environment variable value or empty string.
func GetEnv(key string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	} else {
		logrus.Fatalf("Error reading env var: %s", key)
		return ""
	}
}

// Get integer value from environment variable.
// Accept environment variable (string) and number of bits in the resulting number (integer).
// Return environment variable value (converted to integer) or terminate program with an error.
func GetIntEnv(key string, bitSize int) int64 {
	if value, ok := os.LookupEnv(key); ok {
		number, err := strconv.ParseInt(value, 10, bitSize)
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
