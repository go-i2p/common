// Package session_tag implements the I2P SessionTag and ECIESSessionTag common data structures.
//
// A SessionTag is a 32-byte random number used for session identification in
// I2P's ElGamal/AES+SessionTag encryption layer.
//
// An ECIESSessionTag is an 8-byte session tag that is a fundamental property
// of the ECIES-X25519-AEAD-Ratchet protocol. All ECIES-X25519 destinations
// and routers use 8-byte session tags (regardless of I2NP message type),
// in contrast to the legacy 32-byte ElGamal/AES+SessionTag form.
//
// Both types provide constant-time equality comparison via crypto/subtle to
// prevent timing side-channel attacks on session tag lookups.
//
// Both types implement the TagIdentifier interface, allowing polymorphic
// handling in protocol code that operates on either tag type generically.
//
// # Design Rationale: Wrapper Struct vs Bare Array
//
// SessionTag and ECIESSessionTag use a wrapper struct (struct{value [N]byte})
// rather than a bare array type (type T [N]byte) as used by the sibling
// session_key package. The wrapper struct approach provides encapsulation —
// callers cannot directly index into the underlying array, so all access goes
// through methods (Bytes, SetBytes, Equal, etc.). This prevents accidental
// mutation and ensures constant-time comparison is always used.
//
// The sibling session_key package uses a bare array type, which allows direct
// == comparison and use as a map key. Both approaches are valid Go idioms with
// different tradeoffs: bare arrays are simpler and map-key-friendly; wrapper
// structs enforce encapsulation and method-based access.
//
// # Usage
//
// Create a random session tag:
//
//	tag, err := session_tag.NewRandomSessionTag()
//
// Read a session tag from wire data:
//
//	tag, remainder, err := session_tag.ReadSessionTag(data)
//
// Use the TagIdentifier interface for polymorphic handling:
//
//	func logTag(t session_tag.TagIdentifier) {
//	    fmt.Println(t.String())
//	}
//
// Specification references:
//   - https://geti2p.net/spec/common-structures#session-tag
//   - https://geti2p.net/spec/ecies
//   - https://geti2p.net/spec/i2np#databaselookup
package session_tag
