// Package session_key implements the I2P SessionKey common data structure
package session_key

import (
	"crypto/subtle"
	"fmt"

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
