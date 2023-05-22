package main

import "os"

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func concatMultipleSlices[T any](slices ...[]T) []T {
	total := 0
	for _, s := range slices {
		total += len(s)
	}

	result := make([]T, total)

	counter := 0
	for _, s := range slices {
		counter += copy(result[counter:], s)
	}

	return result
}
