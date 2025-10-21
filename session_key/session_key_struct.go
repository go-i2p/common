// Package session_key implements the I2P SessionKey common data structure
package session_key

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

/*
[SessionKey]
Accurate for version 0.9.49

Description
This structure is used for symmetric AES256 encryption and decryption.

Contents
32 bytes
*/

// SessionKey is the represenation of an I2P SessionKey.
//
// https://geti2p.net/spec/common-structures#sessionkey
type SessionKey [SESSION_KEY_SIZE]byte

var log = logger.GetGoI2PLogger()

// NewSessionKey creates a new *SessionKey from []byte using ReadSessionKey.
// Returns a pointer to SessionKey unlike ReadSessionKey.
func NewSessionKey(data []byte) (session_key *SessionKey, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Creating new SessionKey")
	sessionKey, remainder, err := ReadSessionKey(data)
	if err != nil {
		log.WithError(err).Error("Failed to create new SessionKey")
		return nil, remainder, err
	}
	session_key = &sessionKey
	log.Debug("Successfully created new SessionKey")
	return
}

// ReadSessionKey returns SessionKey from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadSessionKey(bytes []byte) (info SessionKey, remainder []byte, err error) {
	if len(bytes) < SESSION_KEY_SIZE {
		log.WithFields(logger.Fields{
			"at":          "(SessionKey) ReadSessionKey",
			"data_length": len(bytes),
			"required":    SESSION_KEY_SIZE,
		}).Error("data too short for SessionKey")
		err = oops.Errorf("ReadSessionKey: data too short, need %d bytes, got %d", SESSION_KEY_SIZE, len(bytes))
		return
	}

	copy(info[:], bytes[:SESSION_KEY_SIZE])
	remainder = bytes[SESSION_KEY_SIZE:]

	log.WithFields(logger.Fields{
		"remainder_length": len(remainder),
	}).Debug("Successfully read SessionKey from data")

	return
}
