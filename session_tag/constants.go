// Package session_tag implements the I2P SessionTag common data structure
package session_tag

// SessionTagSize is the size of an I2P SessionTag in bytes.
// According to the I2P specification, a SessionTag is always 32 bytes.
//
// https://geti2p.net/spec/common-structures#session-tag
const SessionTagSize = 32

// ECIESSessionTagSize is the size of an ECIES-X25519-AEAD-Ratchet session tag.
// When the ECIES flag is set in I2NP messages, session tags are 8 bytes.
// Used throughout the ECIES-X25519-AEAD-Ratchet protocol for new session reply
// and existing session message formats.
//
// https://geti2p.net/spec/i2np#databaselookup
// https://geti2p.net/spec/ecies
const ECIESSessionTagSize = 8
