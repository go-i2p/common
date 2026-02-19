package session_key

// ————————————————————————————————————————————————
// Shared test helpers for the session_key package
// ————————————————————————————————————————————————

// makeSessionKeyBytes creates a SESSION_KEY_SIZE byte slice filled with the given pattern byte.
func makeSessionKeyBytes(pattern byte) []byte {
	b := make([]byte, SESSION_KEY_SIZE)
	for i := range b {
		b[i] = pattern
	}
	return b
}

// makeSequentialBytes creates a SESSION_KEY_SIZE byte slice with sequential values.
func makeSequentialBytes() []byte {
	b := make([]byte, SESSION_KEY_SIZE)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}
