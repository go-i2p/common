package session_key

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

/*
[SessionKey]
Accurate for version 0.9.67

Description
This structure is used for symmetric AES256 encryption and decryption.

Contents
32 bytes
*/

// SessionKey is the representation of an I2P SessionKey.
//
// https://geti2p.net/spec/common-structures#sessionkey
type SessionKey [SESSION_KEY_SIZE]byte

var log = logger.GetGoI2PLogger()

// Bytes returns the SessionKey as a byte slice.
//
// Because Bytes uses a value receiver, the returned slice is backed by a copy
// of the key array. Mutations to the returned slice do NOT affect this
// SessionKey, and zeroing the returned slice does NOT erase this key's
// material. To securely erase key material, call Zeroize() on the original
// SessionKey pointer.
func (sk SessionKey) Bytes() []byte {
	return sk[:]
}

// Equal checks if two SessionKeys are equal using constant-time comparison
// to prevent timing side-channel attacks.
func (sk SessionKey) Equal(other SessionKey) bool {
	return subtle.ConstantTimeCompare(sk[:], other[:]) == 1
}

// String returns a hex representation of the SessionKey for debugging.
func (sk SessionKey) String() string {
	return fmt.Sprintf("%x", sk[:])
}

// SetBytes sets the SessionKey value from a byte slice.
// The input must be exactly SESSION_KEY_SIZE bytes long.
//
// If the input slice may contain trailing bytes (e.g. when parsing from a
// network buffer), use ReadSessionKey instead — it accepts len >= SESSION_KEY_SIZE
// and returns the remaining bytes as the second return value.
func (sk *SessionKey) SetBytes(data []byte) error {
	if len(data) != SESSION_KEY_SIZE {
		return oops.Errorf("SetBytes: invalid data length, expected %d bytes, got %d", SESSION_KEY_SIZE, len(data))
	}
	copy(sk[:], data)
	return nil
}

// IsZero returns true if the SessionKey is all zeros (uninitialized).
func (sk SessionKey) IsZero() bool {
	var zero SessionKey
	return subtle.ConstantTimeCompare(sk[:], zero[:]) == 1
}

// NewSessionKey creates a new *SessionKey from []byte using ReadSessionKey.
// Returns a pointer to SessionKey unlike ReadSessionKey.
func NewSessionKey(data []byte) (sessionKey *SessionKey, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Creating new SessionKey")
	sk, remainder, err := ReadSessionKey(data)
	if err != nil {
		log.WithError(err).Error("Failed to create new SessionKey")
		return nil, remainder, err
	}
	sessionKey = &sk
	log.Debug("Successfully created new SessionKey")
	return
}

// NewSessionKeyFromArray creates a SessionKey from a fixed-size byte array.
// This provides zero-copy construction when a [SESSION_KEY_SIZE]byte is already available.
func NewSessionKeyFromArray(data [SESSION_KEY_SIZE]byte) SessionKey {
	return SessionKey(data)
}

// ReadSessionKey returns SessionKey from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns an error if the data is too short to contain a valid SessionKey.
func ReadSessionKey(bytes []byte) (sessionKey SessionKey, remainder []byte, err error) {
	if len(bytes) < SESSION_KEY_SIZE {
		log.WithFields(logger.Fields{
			"at":          "(SessionKey) ReadSessionKey",
			"data_length": len(bytes),
			"required":    SESSION_KEY_SIZE,
		}).Error("data too short for SessionKey")
		err = oops.Errorf("ReadSessionKey: data too short, need %d bytes, got %d", SESSION_KEY_SIZE, len(bytes))
		return
	}

	copy(sessionKey[:], bytes[:SESSION_KEY_SIZE])
	remainder = bytes[SESSION_KEY_SIZE:]

	log.WithFields(logger.Fields{
		"remainder_length": len(remainder),
	}).Debug("Successfully read SessionKey from data")

	return
}

// GenerateSessionKey creates a new SessionKey filled with cryptographically
// secure random bytes from crypto/rand. This is the recommended way to create
// new session keys for AES-256 encryption.
func GenerateSessionKey() (SessionKey, error) {
	var sk SessionKey
	_, err := rand.Read(sk[:])
	if err != nil {
		return SessionKey{}, oops.Errorf("GenerateSessionKey: failed to read random bytes: %w", err)
	}
	log.Debug("Generated new random SessionKey")
	return sk, nil
}

// Zeroize overwrites the SessionKey with zeros, erasing key material from
// memory. Call this when the key is no longer needed to limit exposure of
// sensitive material. Note: Go's garbage collector may have already copied
// the value elsewhere; this is a best-effort defense-in-depth measure.
func (sk *SessionKey) Zeroize() {
	for i := range sk {
		sk[i] = 0
	}
}

// MarshalBinary implements encoding.BinaryMarshaler.
// It returns a copy of the SessionKey's bytes.
func (sk SessionKey) MarshalBinary() ([]byte, error) {
	b := make([]byte, SESSION_KEY_SIZE)
	copy(b, sk[:])
	return b, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
// The input must be exactly SESSION_KEY_SIZE (32) bytes.
func (sk *SessionKey) UnmarshalBinary(data []byte) error {
	if len(data) != SESSION_KEY_SIZE {
		return oops.Errorf("UnmarshalBinary: invalid data length, expected %d bytes, got %d", SESSION_KEY_SIZE, len(data))
	}
	copy(sk[:], data)
	return nil
}

// ReadFrom reads exactly SESSION_KEY_SIZE bytes from r into the SessionKey.
// Implements io.ReaderFrom. Returns the number of bytes read and any error.
// Use this to avoid allocating an intermediate buffer when reading from a
// net.Conn or bytes.Reader in protocol-level code.
func (sk *SessionKey) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.ReadFull(r, sk[:])
	if err != nil {
		*sk = SessionKey{}
		return int64(n), oops.Errorf("SessionKey.ReadFrom: %w", err)
	}
	return int64(n), nil
}

// WriteTo writes the SESSION_KEY_SIZE bytes of the SessionKey to w.
// Implements io.WriterTo. Returns the number of bytes written and any error.
func (sk SessionKey) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(sk[:])
	if err != nil {
		return int64(n), oops.Errorf("SessionKey.WriteTo: %w", err)
	}
	return int64(n), nil
}

// FromHex parses a lowercase or uppercase hex-encoded string into a SessionKey.
// The string must encode exactly SESSION_KEY_SIZE bytes (64 hex characters).
// This is the symmetric counterpart to String().
func FromHex(s string) (SessionKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return SessionKey{}, oops.Errorf("FromHex: %w", err)
	}
	if len(b) != SESSION_KEY_SIZE {
		return SessionKey{}, oops.Errorf("FromHex: expected %d bytes, got %d", SESSION_KEY_SIZE, len(b))
	}
	var sk SessionKey
	copy(sk[:], b)
	return sk, nil
}

// FromBase64 parses a standard base64-encoded string (with or without padding)
// into a SessionKey. The decoded bytes must be exactly SESSION_KEY_SIZE.
func FromBase64(s string) (SessionKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// Also try without padding
		b, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return SessionKey{}, oops.Errorf("FromBase64: %w", err)
		}
	}
	if len(b) != SESSION_KEY_SIZE {
		return SessionKey{}, oops.Errorf("FromBase64: expected %d bytes, got %d", SESSION_KEY_SIZE, len(b))
	}
	var sk SessionKey
	copy(sk[:], b)
	return sk, nil
}
