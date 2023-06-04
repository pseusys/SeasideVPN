package main

import "os"

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func Min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}
