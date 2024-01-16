package utils

func ConcatSlices[T any](slices ...[]T) []T {
	var totalLength int
	for _, slice := range slices {
		totalLength += len(slice)
	}

	iterator := 0
	container := make([]T, totalLength)
	for _, slice := range slices {
		iterator += copy(container[iterator:], slice)
	}
	return container
}
