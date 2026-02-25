// Package session_tag implements the I2P SessionTag common data structure
package session_tag

// SessionTagSize is the size of an I2P SessionTag in bytes.
// According to the I2P specification, a SessionTag is always 32 bytes.
//
// https://geti2p.net/spec/common-structures#session-tag
const SessionTagSize = 32

// ECIESSessionTagSize is the size of a session tag in the
// ECIES-X25519-AEAD-Ratchet protocol. 8-byte session tags are a fundamental
// property of this protocol (used for both new-session-reply and
// existing-session messages) regardless of I2NP message type. This is
// distinct from the legacy 32-byte ElGamal/AES+SessionTag form.
//
// https://geti2p.net/spec/common-structures#session-tag
// https://geti2p.net/spec/ecies
const ECIESSessionTagSize = 8
