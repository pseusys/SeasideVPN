package utils

// Count set bits in a number.
// Accept unsigned 64-bit integer.
// Return integer (from 0 to 64): number of set bits.
func CountSetBits(num uint64) int {
	count := 0
	for num > 0 {
		count += int(num & 1)
		num >>= 1
	}
	return count
}
