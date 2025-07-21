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

// Int returns the Integer as a Go integer. Returns 0 if conversion fails.
func (i Integer) Int() int {
	value, err := intFromBytes(i.Bytes())
	if err != nil {
		// Log error context for debugging
		// (logging already handled in intFromBytes)
		return 0
	}
	return value
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

// validateIntegerInput validates that the input value and size are valid for integer creation.
// Returns error if value is negative or size is invalid.
func validateIntegerInput(value int, size int) error {
	if value < 0 {
		return oops.Errorf("cannot create integer from negative value: %d", value)
	}
	return nil
}

// calculateMaxValueForSize calculates the maximum value that can fit in the specified byte size.
// Returns the maximum uint64 value for the given size in bytes.
func calculateMaxValueForSize(size int) uint64 {
	if size >= 8 {
		return math.MaxUint64
	}
	return uint64(1<<(size*BITS_PER_BYTE)) - 1
}

// validateValueBounds checks if the value fits within the maximum allowed for the specified size.
// Returns error if value exceeds the maximum for the given byte size.
func validateValueBounds(value int, size int, maxValue uint64) error {
	if uint64(value) > maxValue {
		return oops.Errorf("value %d exceeds maximum for %d bytes (max: %d)", value, size, maxValue)
	}
	return nil
}

// createIntegerFromBytes creates an Integer from a uint64 value using the specified byte size.
// Returns the created Integer and any error from the construction process.
func createIntegerFromBytes(value int, size int) (*Integer, error) {
	bytes := make([]byte, MAX_INTEGER_SIZE)
	binary.BigEndian.PutUint64(bytes, uint64(value))

	integerSize := MAX_INTEGER_SIZE
	if size < MAX_INTEGER_SIZE {
		integerSize = size
	}

	objinteger, _, err := NewInteger(bytes[MAX_INTEGER_SIZE-integerSize:], integerSize)
	return objinteger, err
}

// NewIntegerFromInt creates a new Integer from a Go integer of a specified []byte length.
func NewIntegerFromInt(value int, size int) (integer *Integer, err error) {
	if err = validateIntegerInput(value, size); err != nil {
		return
	}

	maxValue := calculateMaxValueForSize(size)
	if err = validateValueBounds(value, size, maxValue); err != nil {
		return
	}

	return createIntegerFromBytes(value, size)
}
