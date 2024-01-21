package utils

import "testing"

func CountSetBitsTest(test *testing.T) {
	binaryNumber := uint64(0b0101001011101101)
	expectedBitSetCount := 9
	bitSetCount := CountSetBits(binaryNumber)
	if bitSetCount != expectedBitSetCount {
		test.Fatalf("set bit count doesn't match expected for int %16b: %d != %d", binaryNumber, bitSetCount, expectedBitSetCount)
	}
}
