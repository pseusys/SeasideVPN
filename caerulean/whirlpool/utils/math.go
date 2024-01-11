package utils

func Min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func Xor(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func CountSetBits(num uint64) int {
	count := 0
	for num > 0 {
		count += int(num & 1)
		num >>= 1
	}
	return count
}
