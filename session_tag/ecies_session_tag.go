package session_tag

import (
	"crypto/subtle"
	"fmt"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ECIESSessionTag is an 8-byte session tag used with the
// ECIES-X25519-AEAD-Ratchet protocol. 8-byte tags are a fundamental property
// of this protocol (for all ECIES-X25519 destinations and routers), not
// limited to any specific I2NP message type.
//
// https://geti2p.net/spec/common-structures#session-tag
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

// EqualBytes performs a constant-time equality check against a raw byte slice.
// Returns false if the lengths differ, avoiding out-of-bounds panics.
func (st ECIESSessionTag) EqualBytes(other []byte) bool {
	return subtle.ConstantTimeCompare(st.value[:], other) == 1
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
func ReadECIESSessionTag(data []byte) (info ECIESSessionTag, remainder []byte, err error) {
	if len(data) < ECIESSessionTagSize {
		log.WithFields(logger.Fields{
			"at":          "(ECIESSessionTag) ReadECIESSessionTag",
			"data_length": len(data),
			"required":    ECIESSessionTagSize,
		}).Error("data too short for ECIESSessionTag")
		err = oops.Errorf(
			"data too short: need %d bytes, got %d",
			ECIESSessionTagSize, len(data),
		)
		return
	}

	copy(info.value[:], data[:ECIESSessionTagSize])
	remainder = data[ECIESSessionTagSize:]

	log.WithFields(logger.Fields{
		"remainder_length": len(remainder),
	}).Debug("Successfully read ECIESSessionTag from data")

	return
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
