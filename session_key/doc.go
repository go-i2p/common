// Package session_key implements the I2P SessionKey common data structure.
//
// A SessionKey is a 32-byte value used for symmetric AES-256 encryption and
// decryption in the I2P network. SessionKeys are used to encrypt tunnel
// messages and garlic cloves.
//
// # Specification
//
// From the I2P Common Structures specification:
//
//	SessionKey :: 32 bytes
//
// See https://geti2p.net/spec/common-structures#sessionkey
//
// # Design
//
// SessionKey is defined as a bare fixed-size array type ([32]byte) rather than
// a wrapper struct. This means SessionKey values are directly comparable with
// == and can be used as map keys, which is convenient for session management.
// The tradeoff is that Bytes() returns a slice aliasing the underlying array,
// so callers should not mutate the returned slice unless they intend to modify
// the key. The sibling session_tag package uses a wrapper struct instead; both
// approaches are valid Go idioms with different tradeoffs.
//
// # Usage
//
//	// Generate a random session key
//	sk, err := session_key.GenerateSessionKey()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Parse a session key from wire format
//	sk, remainder, err := session_key.ReadSessionKey(data)
//
//	// Constant-time comparison (safe for cryptographic use)
//	if sk.Equal(other) { ... }
//
//	// Secure zeroing when done
//	sk.Zeroize()
package session_key
