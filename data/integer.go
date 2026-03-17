package data

import (
	"encoding/binary"
	"math"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

/*
[I2P Integer]
Accurate for version 0.9.67

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
// WARNING: For 8-byte values >= 2^63, this method returns 0 because the unsigned
// I2P Integer exceeds Go's signed int range. Use UintSafe() for the full unsigned range.
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
// Size must be between 1 and MAX_INTEGER_SIZE (8) inclusive.
func ReadInteger(bytes []byte, size int) (Integer, []byte) {
	if size <= 0 || size > MAX_INTEGER_SIZE {
		log.WithFields(logger.Fields{
			"size": size,
			"max":  MAX_INTEGER_SIZE,
		}).Error("ReadInteger: invalid size parameter")
		return nil, bytes
	}
	if len(bytes) < size {
		log.WithFields(logger.Fields{
			"available": len(bytes),
			"requested": size,
		}).Error("ReadInteger: insufficient data")
		return nil, bytes
	}
	return bytes[:size], bytes[size:]
}

// NewInteger creates a new Integer from []byte using ReadInteger.
// Deprecated: Use ReadInteger and take address if pointer needed. This function will be removed in v2.0.
// Returns a pointer to Integer unlike ReadInteger.
func NewInteger(bytes []byte, size int) (integer *Integer, remainder []byte, err error) {
	i, remainder := ReadInteger(bytes, size)
	if i == nil {
		return nil, remainder, oops.Errorf("NewInteger: failed to read integer (invalid size or insufficient data)")
	}
	integer = &i
	return integer, remainder, err
}

// validateIntegerInput validates that the input value and size are valid for integer creation.
// Returns error if value is negative or size is invalid.
func validateIntegerInput(value, size int) error {
	if value < 0 {
		return oops.Errorf("cannot create integer from negative value: %d", value)
	}
	if size < 1 || size > MAX_INTEGER_SIZE {
		return oops.Errorf("invalid integer size: %d (must be 1-%d)", size, MAX_INTEGER_SIZE)
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
func validateValueBounds(value, size int, maxValue uint64) error {
	if uint64(value) > maxValue {
		return oops.Errorf("value %d exceeds maximum for %d bytes (max: %d)", value, size, maxValue)
	}
	return nil
}

// createIntegerFromBytes creates an Integer from a uint64 value using the specified byte size.
// Returns the created Integer and any error from the construction process.
func createIntegerFromBytes(value, size int) (*Integer, error) {
	bytes := make([]byte, MAX_INTEGER_SIZE)
	binary.BigEndian.PutUint64(bytes, uint64(value))

	integerSize := MAX_INTEGER_SIZE
	if size < MAX_INTEGER_SIZE {
		integerSize = size
	}

	i, _ := ReadInteger(bytes[MAX_INTEGER_SIZE-integerSize:], integerSize)
	if i == nil {
		return nil, oops.Errorf("failed to create integer from bytes")
	}
	return &i, nil
}

// NewIntegerFromInt creates a new Integer from a Go integer of a specified []byte length.
func NewIntegerFromInt(value, size int) (integer *Integer, err error) {
	if err = validateIntegerInput(value, size); err != nil {
		return integer, err
	}

	maxValue := calculateMaxValueForSize(size)
	if err = validateValueBounds(value, size, maxValue); err != nil {
		return integer, err
	}

	return createIntegerFromBytes(value, size)
}

// NewIntegerFromBytes creates a validated Integer from a byte slice.
// Returns error if bytes is empty or exceeds maximum integer size.
// This is the recommended safe constructor for creating Integers from raw bytes.
func NewIntegerFromBytes(bytes []byte) (Integer, error) {
	if len(bytes) == 0 {
		return nil, oops.Errorf("integer cannot be empty")
	}
	if len(bytes) > MAX_INTEGER_SIZE {
		return nil, oops.Errorf("integer too large: %d bytes (max %d)",
			len(bytes), MAX_INTEGER_SIZE)
	}
	i := make(Integer, len(bytes))
	copy(i, bytes)
	return i, nil
}

// IntSafe returns the Integer as a Go int with error handling.
// Unlike Int(), this method returns an error instead of defaulting to 0.
// Use this method when you need to distinguish between actual zero values and errors.
// WARNING: For 8-byte values >= 2^63, this returns an error because the unsigned
// I2P Integer exceeds Go's signed int range. Use UintSafe() for the full unsigned range.
func (i Integer) IntSafe() (int, error) {
	if len(i) == 0 {
		return 0, oops.Errorf("cannot convert empty integer")
	}
	if len(i) > MAX_INTEGER_SIZE {
		return 0, oops.Errorf("integer too large: %d bytes", len(i))
	}
	return intFromBytes(i.Bytes())
}

// UintSafe returns the Integer as a Go uint64 with error handling.
// This method correctly handles unsigned integers per the I2P spec,
// which defines Integer as "an unsigned integer." Values with the high bit set
// are returned correctly as large positive values, unlike Int()/IntSafe()
// which may wrap negative for 8-byte values >= 2^63.
func (i Integer) UintSafe() (uint64, error) {
	if len(i) == 0 {
		return 0, oops.Errorf("cannot convert empty integer")
	}
	if len(i) > MAX_INTEGER_SIZE {
		return 0, oops.Errorf("integer too large: %d bytes", len(i))
	}
	numLen := len(i)
	number := i.Bytes()
	if numLen < MAX_INTEGER_SIZE {
		paddedNumber := make([]byte, MAX_INTEGER_SIZE)
		copy(paddedNumber[MAX_INTEGER_SIZE-numLen:], number)
		number = paddedNumber
	}
	return binary.BigEndian.Uint64(number), nil
}

// IsZero returns true if the integer represents a valid zero value.
// All bytes in the integer must be 0x00 for this to return true.
// Returns false for nil or empty Integers, since a zero-length Integer is invalid
// per the I2P spec (Integers must be 1–8 bytes). Use IsValid() to check whether
// an Integer has valid length before calling IsZero().
func (i Integer) IsZero() bool {
	if len(i) == 0 {
		return false
	}
	for _, b := range i {
		if b != 0 {
			return false
		}
	}
	return true
}

// IsValid returns true if the Integer has a valid byte length per the I2P spec.
// Valid Integers are 1–8 bytes (inclusive). Nil or empty Integers are invalid.
func (i Integer) IsValid() bool {
	return len(i) >= 1 && len(i) <= MAX_INTEGER_SIZE
}

// Validate checks that the Integer is structurally valid per the I2P spec.
// Returns an error if the Integer is empty or exceeds the maximum size of 8 bytes.
func (i Integer) Validate() error {
	if len(i) == 0 {
		return oops.Errorf("Integer is empty")
	}
	if len(i) > MAX_INTEGER_SIZE {
		return oops.Errorf("Integer too large: %d bytes (max %d)", len(i), MAX_INTEGER_SIZE)
	}
	return nil
}
