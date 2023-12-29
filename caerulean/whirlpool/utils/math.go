package utils

func ModInverse(a, m uint16) uint16 {
	g := a
	x := uint16(0)
	y := uint16(1)
	u := uint16(1)
	v := uint16(0)

	for g != 0 {
		q := m / g
		t := g
		g = m % g
		m = t
		t = x
		x = u - q*x
		u = t
		t = y
		y = v - q*y
		v = t
	}

	result := u + m
	return result
}

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
