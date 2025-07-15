// Package session_tag implements the I2P SessionTag common data structure
package session_tag

import (
	"fmt"

	"github.com/samber/oops"
)

/*
[SessionTag]
Accurate for version 0.9.49

Description
A random number

Contents
32 bytes
*/

// SessionTag is the representation of an I2P SessionTag.
// A SessionTag is a 32-byte random number used in I2P for session identification.
//
// https://geti2p.net/spec/common-structures#session-tag
type SessionTag struct {
	// value contains the 32-byte session identifier
	// This is a random number used for session identification in I2P
	value [SessionTagSize]byte
}

// Bytes returns the SessionTag as a byte slice.
// This method provides compatibility with code that expects []byte.
func (st SessionTag) Bytes() []byte {
	return st.value[:]
}

// Array returns the SessionTag as a byte array.
// This method provides access to the underlying fixed-size array.
func (st SessionTag) Array() [SessionTagSize]byte {
	return st.value
}

// SetBytes sets the SessionTag value from a byte slice.
// The input must be exactly SessionTagSize bytes long.
func (st *SessionTag) SetBytes(data []byte) error {
	if len(data) != SessionTagSize {
		return oops.Errorf("invalid data length: expected %d bytes, got %d", SessionTagSize, len(data))
	}
	copy(st.value[:], data)
	return nil
}

// Equal checks if two SessionTags are equal.
func (st SessionTag) Equal(other SessionTag) bool {
	return st.value == other.value
}

// String returns a hex representation of the SessionTag for debugging.
func (st SessionTag) String() string {
	return fmt.Sprintf("%x", st.value[:])
}

// NewSessionTagFromBytes creates a new SessionTag from a byte slice.
// The input must be exactly SessionTagSize bytes long.
func NewSessionTagFromBytes(data []byte) (SessionTag, error) {
	var st SessionTag
	err := st.SetBytes(data)
	return st, err
}

// NewSessionTagFromArray creates a new SessionTag from a byte array.
func NewSessionTagFromArray(data [SessionTagSize]byte) SessionTag {
	return SessionTag{value: data}
}
