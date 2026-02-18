package signature

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// Validate checks if the Signature is properly initialized and valid.
// Returns an error if the signature has an unknown type or has incorrect data size.
//
// Byte order note per I2P spec:
//   - All signature types are Big Endian, EXCEPT EdDSA and RedDSA
//     (types 7, 8, 11), which are stored and transmitted in Little Endian format.
//   - This method does not validate byte order; it validates type and length only.
func (s Signature) Validate() error {
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
func (s Signature) IsValid() bool {
	return s.Validate() == nil
}

// ValidatePtr checks if the Signature pointer is non-nil and the Signature is valid.
// Returns an error if the pointer is nil or the signature is invalid.
func ValidatePtr(s *Signature) error {
	if s == nil {
		return oops.Errorf("signature is nil")
	}
	return s.Validate()
}
