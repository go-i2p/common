package base32

import (
	"crypto/sha256"
	"strings"
)

// Shared test helpers for the base32 package

// sha256Sum returns the SHA-256 hash of data as a [32]byte.
func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// trimRight wraps strings.TrimRight for use in tests.
func trimRight(s, cutset string) string {
	return strings.TrimRight(s, cutset)
}
