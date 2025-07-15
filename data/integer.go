package data

import (
	"encoding/binary"
	"math"

	"github.com/samber/oops"
)

/*
[I2P Integer]
Accurate for version 0.9.49

Description
Represents a non-negative integer.

Contents
1 to 8 bytes in network byte order (big endian) representing an unsigned integer.
*/

// Integer is the represenation of an I2P Integer.
//
// https://geti2p.net/spec/common-structures#integer
type Integer []byte

// Bytes returns the raw []byte content of an Integer.
func (i Integer) Bytes() []byte {
	return i[:]
}

// Int returns the Integer as a Go integer
func (i Integer) Int() int {
	return intFromBytes(i.Bytes())
}

// ReadInteger returns an Integer from a []byte of specified length.
// The remaining bytes after the specified length are also returned.
func ReadInteger(bytes []byte, size int) (Integer, []byte) {
	if len(bytes) < size {
		return bytes, nil
	}
	return bytes[:size], bytes[size:]
}

// NewInteger creates a new Integer from []byte using ReadInteger.
// Deprecated: Use ReadInteger and take address if pointer needed. This function will be removed in v2.0.
// Returns a pointer to Integer unlike ReadInteger.
func NewInteger(bytes []byte, size int) (integer *Integer, remainder []byte, err error) {
	i, remainder := ReadInteger(bytes, size)
	integer = &i
	return
}

// NewIntegerFromInt creates a new Integer from a Go integer of a specified []byte length.
func NewIntegerFromInt(value int, size int) (integer *Integer, err error) {
	// Validate that the value fits in the specified byte size
	if value < 0 {
		err = oops.Errorf("cannot create integer from negative value: %d", value)
		return
	}

	// Calculate maximum value that can fit in the specified size
	var maxValue uint64
	if size >= 8 {
		maxValue = math.MaxUint64
	} else {
		maxValue = uint64(1<<(size*BITS_PER_BYTE)) - 1
	}
	if uint64(value) > maxValue {
		err = oops.Errorf("value %d exceeds maximum for %d bytes (max: %d)", value, size, maxValue)
		return
	}

	bytes := make([]byte, MAX_INTEGER_SIZE)
	binary.BigEndian.PutUint64(bytes, uint64(value))
	integerSize := MAX_INTEGER_SIZE
	if size < MAX_INTEGER_SIZE {
		integerSize = size
	}
	objinteger, _, err := NewInteger(bytes[MAX_INTEGER_SIZE-integerSize:], integerSize)
	integer = objinteger
	return
}
