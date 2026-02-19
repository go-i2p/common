package session_tag

// makeSessionTagBytes creates a [SessionTagSize]byte array filled with the given byte.
func makeSessionTagBytes(fill byte) [SessionTagSize]byte {
	var b [SessionTagSize]byte
	for i := range b {
		b[i] = fill
	}
	return b
}

// makeECIESSessionTagBytes creates a [ECIESSessionTagSize]byte array filled with the given byte.
func makeECIESSessionTagBytes(fill byte) [ECIESSessionTagSize]byte {
	var b [ECIESSessionTagSize]byte
	for i := range b {
		b[i] = fill
	}
	return b
}

// makeSequentialSessionTagBytes creates a [SessionTagSize]byte array with sequential values starting at 1.
func makeSequentialSessionTagBytes() []byte {
	b := make([]byte, SessionTagSize)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

// makeSequentialECIESBytes creates an [ECIESSessionTagSize]byte slice with sequential values starting at 1.
func makeSequentialECIESBytes() []byte {
	b := make([]byte, ECIESSessionTagSize)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}
