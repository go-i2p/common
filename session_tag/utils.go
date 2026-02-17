// Package session_tag implements the I2P SessionTag common data structure
package session_tag

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// ReadSessionTag returns SessionTag from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadSessionTag(bytes []byte) (info SessionTag, remainder []byte, err error) {
	if len(bytes) < SessionTagSize {
		log.WithFields(logger.Fields{
			"at":          "(SessionTag) ReadSessionTag",
			"data_length": len(bytes),
			"required":    SessionTagSize,
		}).Error("data too short for SessionTag")
		err = oops.Errorf("ReadSessionTag: data too short, need %d bytes, got %d", SessionTagSize, len(bytes))
		return
	}

	copy(info.value[:], bytes[:SessionTagSize])
	remainder = bytes[SessionTagSize:]

	log.WithFields(logger.Fields{
		"remainder_length": len(remainder),
	}).Debug("Successfully read SessionTag from data")

	return
}

// NewSessionTag creates a new *SessionTag from []byte using ReadSessionTag.
// Returns a pointer to SessionTag unlike ReadSessionTag.
func NewSessionTag(data []byte) (sessionTag *SessionTag, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Creating new SessionTag")
	st, remainder, err := ReadSessionTag(data)
	if err != nil {
		log.WithError(err).Error("Failed to read SessionTag")
		return nil, remainder, err
	}
	sessionTag = &st
	log.WithFields(logger.Fields{
		"remainder_length": len(remainder),
	}).Debug("Successfully created new SessionTag")
	return
}
