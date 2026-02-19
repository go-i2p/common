package key_certificate

// makeTestBytes creates a byte slice of the given size filled with sequential values
// starting from startByte. Useful for creating non-zero test data with predictable patterns.
func makeTestBytes(size int, startByte byte) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(int(startByte) + i)
	}
	return b
}
