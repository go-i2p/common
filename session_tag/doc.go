// Package session_tag implements the I2P SessionTag and ECIESSessionTag common data structures.
//
// A SessionTag is a 32-byte random number used for session identification in
// I2P's ElGamal/AES+SessionTag encryption layer.
//
// An ECIESSessionTag is an 8-byte session tag used with the newer
// ECIES-X25519-AEAD-Ratchet protocol. When the ECIESFlag (bit 4) is set in
// I2NP DatabaseLookup messages, reply session tags use this shorter format.
//
// Both types provide constant-time equality comparison via crypto/subtle to
// prevent timing side-channel attacks on session tag lookups.
//
// Specification references:
//   - https://geti2p.net/spec/common-structures#session-tag
//   - https://geti2p.net/spec/ecies
//   - https://geti2p.net/spec/i2np#databaselookup
package session_tag
