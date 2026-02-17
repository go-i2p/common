package session_tag

import (
	"crypto/subtle"
	"fmt"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ECIESSessionTag is an 8-byte session tag used with ECIES-X25519-AEAD-Ratchet.
// When the ECIESFlag (bit 4) is set in DatabaseLookup messages, reply session
// tags are 8 bytes instead of the standard 32-byte ElGamal/AES SessionTag.
//
// https://geti2p.net/spec/i2np#databaselookup
// https://geti2p.net/spec/ecies
type ECIESSessionTag struct {
	value [ECIESSessionTagSize]byte
}

// Bytes returns the ECIESSessionTag as a byte slice.
// This method provides compatibility with code that expects []byte.
func (st ECIESSessionTag) Bytes() []byte {
	return st.value[:]
}

// Array returns the ECIESSessionTag as a byte array.
// This method provides access to the underlying fixed-size array.
func (st ECIESSessionTag) Array() [ECIESSessionTagSize]byte {
	return st.value
}

// SetBytes sets the ECIESSessionTag value from a byte slice.
// The input must be exactly ECIESSessionTagSize bytes long.
func (st *ECIESSessionTag) SetBytes(data []byte) error {
	if len(data) != ECIESSessionTagSize {
		return oops.Errorf(
			"invalid data length: expected %d bytes, got %d",
			ECIESSessionTagSize, len(data),
		)
	}
	copy(st.value[:], data)
	return nil
}

// Equal checks if two ECIESSessionTags are equal using constant-time comparison
// to prevent timing side-channel attacks on session tag lookups.
func (st ECIESSessionTag) Equal(other ECIESSessionTag) bool {
	return subtle.ConstantTimeCompare(st.value[:], other.value[:]) == 1
}

// String returns a hex representation of the ECIESSessionTag for debugging.
func (st ECIESSessionTag) String() string {
	return fmt.Sprintf("%x", st.value[:])
}

// IsZero returns true if the ECIESSessionTag is the zero value (all bytes are 0x00).
// This is useful for detecting uninitialized tags when stored in maps or used as sentinels.
func (st ECIESSessionTag) IsZero() bool {
	var zero [ECIESSessionTagSize]byte
	return subtle.ConstantTimeCompare(st.value[:], zero[:]) == 1
}

// NewECIESSessionTagFromBytes creates a new ECIESSessionTag from a byte slice.
// The input must be exactly ECIESSessionTagSize bytes long.
func NewECIESSessionTagFromBytes(data []byte) (ECIESSessionTag, error) {
	var st ECIESSessionTag
	err := st.SetBytes(data)
	return st, err
}

// NewECIESSessionTagFromArray creates a new ECIESSessionTag from a byte array.
func NewECIESSessionTagFromArray(data [ECIESSessionTagSize]byte) ECIESSessionTag {
	return ECIESSessionTag{value: data}
}

// ReadECIESSessionTag reads an ECIESSessionTag from a byte slice.
// Returns the ECIESSessionTag, the remaining bytes, and any error.
func ReadECIESSessionTag(data []byte) (ECIESSessionTag, []byte, error) {
	if len(data) < ECIESSessionTagSize {
		log.WithFields(logger.Fields{
			"at":          "(ECIESSessionTag) ReadECIESSessionTag",
			"data_length": len(data),
			"required":    ECIESSessionTagSize,
		}).Error("data too short for ECIESSessionTag")
		return ECIESSessionTag{}, nil, oops.Errorf(
			"data too short: need %d bytes, got %d",
			ECIESSessionTagSize, len(data),
		)
	}

	st, err := NewECIESSessionTagFromBytes(data[:ECIESSessionTagSize])
	if err != nil {
		log.WithError(err).Error("Failed to create ECIESSessionTag from bytes")
		return ECIESSessionTag{}, nil, err
	}

	log.WithFields(logger.Fields{
		"remainder_length": len(data[ECIESSessionTagSize:]),
	}).Debug("Successfully read ECIESSessionTag from data")

	return st, data[ECIESSessionTagSize:], nil
}

// NewECIESSessionTag creates a new ECIESSessionTag from a byte slice.
// Returns a pointer to the ECIESSessionTag, the remaining bytes, and any error.
func NewECIESSessionTag(data []byte) (*ECIESSessionTag, []byte, error) {
	st, remainder, err := ReadECIESSessionTag(data)
	if err != nil {
		return nil, nil, err
	}
	return &st, remainder, nil
}
