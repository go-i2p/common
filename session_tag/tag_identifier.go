package session_tag

import "github.com/go-i2p/crypto/rand"

// TagIdentifier is a common interface implemented by both SessionTag and
// ECIESSessionTag, enabling polymorphic handling of either tag type in
// protocol code that operates on session tags generically.
//
// Both SessionTag (32-byte ElGamal/AES) and ECIESSessionTag (8-byte
// ECIES-X25519-AEAD-Ratchet) satisfy this interface.
type TagIdentifier interface {
	// Bytes returns the tag as a byte slice.
	Bytes() []byte
	// String returns a hex representation of the tag.
	String() string
	// IsZero returns true if the tag is the zero value.
	IsZero() bool
	// EqualBytes performs a constant-time equality check against a raw
	// byte slice. Returns false if lengths differ. This allows polymorphic
	// comparison through the interface without unsafe type assertions.
	EqualBytes(other []byte) bool
}

// Compile-time interface compliance checks.
var (
	_ TagIdentifier = SessionTag{}
	_ TagIdentifier = ECIESSessionTag{}
)

// NewRandomSessionTag creates a new SessionTag filled with cryptographically
// secure random bytes from crypto/rand. Per the I2P specification, a
// SessionTag is "a random number."
//
// https://geti2p.net/spec/common-structures#session-tag
func NewRandomSessionTag() (SessionTag, error) {
	var st SessionTag
	_, err := rand.Read(st.value[:])
	if err != nil {
		return SessionTag{}, err
	}
	return st, nil
}

// NewRandomECIESSessionTag creates a new ECIESSessionTag filled with
// cryptographically secure random bytes from crypto/rand.
//
// Note: In the ECIES-X25519-AEAD-Ratchet protocol, session tags are typically
// ratchet-derived rather than purely random. This constructor is provided for
// testing and for protocols that require random 8-byte tags.
//
// https://geti2p.net/spec/ecies
func NewRandomECIESSessionTag() (ECIESSessionTag, error) {
	var st ECIESSessionTag
	_, err := rand.Read(st.value[:])
	if err != nil {
		return ECIESSessionTag{}, err
	}
	return st, nil
}
