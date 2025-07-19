package utils

// Concatenate arrays.
// Accept vararg of slices.
// Return a joined slice of all the input slices.
func ConcatSlices[T any](slices ...[]T) []T {
	// Calculate slice number
	totalLength := 0
	for _, slice := range slices {
		totalLength += len(slice)
	}

	// Concatenate slices into container array
	iterator := 0
	container := make([]T, totalLength)
	for _, slice := range slices {
		iterator += copy(container[iterator:], slice)
	}
	return container
}

func XORSlices(src, dst []byte) []byte {
	n := min(len(src), len(dst))
	for i := range n {
		src[i] = src[i] ^ dst[i]
	}
	return src
}
