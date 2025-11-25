// Package signature implements the I2P Signature common data structure
package signature

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// Validate checks if the Signature is properly initialized and valid.
// Returns an error if the signature is nil, has an unknown type, or has incorrect data size.
func (s *Signature) Validate() error {
	if s == nil {
		return oops.Errorf("signature is nil")
	}

	// Validate the signature type is supported
	expectedSize, err := getSignatureLength(s.sigType)
	if err != nil {
		return oops.Errorf("invalid signature type %d: %w", s.sigType, err)
	}

	// Validate the signature data size matches the expected size for the type
	if len(s.data) != expectedSize {
		return oops.Errorf("signature data size mismatch for type %d: got %d bytes, expected %d bytes",
			s.sigType, len(s.data), expectedSize)
	}

	return nil
}

// IsValid returns true if the Signature is properly initialized and valid.
// This is a convenience method that calls Validate() and returns false if there's an error.
func (s *Signature) IsValid() bool {
	return s.Validate() == nil
}
