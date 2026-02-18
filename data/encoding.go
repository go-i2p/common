// Package data implements I2P common data structures.
package data

import (
	"encoding/binary"

	"github.com/samber/oops"
)

// EncodeUint16 encodes a uint16 value to a 2-byte big-endian array.
// This is a convenience function for creating fixed-size integers without error handling.
//
// Example:
//
//	bytes := data.EncodeUint16(1234)
//	// bytes = [4, 210] (0x04D2 in big endian)
func EncodeUint16(value uint16) [2]byte {
	var bytes [2]byte
	binary.BigEndian.PutUint16(bytes[:], value)
	return bytes
}

// EncodeUint32 encodes a uint32 value to a 4-byte big-endian array.
// This is a convenience function for creating fixed-size integers without error handling.
//
// Example:
//
//	bytes := data.EncodeUint32(123456)
//	// bytes = [0, 1, 226, 64] (0x0001E240 in big endian)
func EncodeUint32(value uint32) [4]byte {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], value)
	return bytes
}

// EncodeUint64 encodes a uint64 value to an 8-byte big-endian array.
// This is a convenience function for creating fixed-size integers without error handling.
//
// Example:
//
//	bytes := data.EncodeUint64(123456789)
func EncodeUint64(value uint64) [8]byte {
	var bytes [8]byte
	binary.BigEndian.PutUint64(bytes[:], value)
	return bytes
}

// EncodeInt16 encodes an int16 value to a 2-byte big-endian array.
// This is a convenience function for creating fixed-size integers without error handling.
//
// Example:
//
//	bytes := data.EncodeInt16(-1234)
func EncodeInt16(value int16) [2]byte {
	return EncodeUint16(uint16(value))
}

// EncodeInt32 encodes an int32 value to a 4-byte big-endian array.
// This is a convenience function for creating fixed-size integers without error handling.
//
// Example:
//
//	bytes := data.EncodeInt32(-123456)
func EncodeInt32(value int32) [4]byte {
	return EncodeUint32(uint32(value))
}

// EncodeInt64 encodes an int64 value to an 8-byte big-endian array.
// This is a convenience function for creating fixed-size integers without error handling.
//
// Example:
//
//	bytes := data.EncodeInt64(-123456789)
func EncodeInt64(value int64) [8]byte {
	return EncodeUint64(uint64(value))
}

// DecodeUint16 decodes a 2-byte big-endian array to a uint16 value.
//
// Example:
//
//	value := data.DecodeUint16([2]byte{4, 210})
//	// value = 1234
func DecodeUint16(data [2]byte) uint16 {
	return binary.BigEndian.Uint16(data[:])
}

// DecodeUint32 decodes a 4-byte big-endian array to a uint32 value.
//
// Example:
//
//	value := data.DecodeUint32([4]byte{0, 1, 226, 64})
//	// value = 123456
func DecodeUint32(data [4]byte) uint32 {
	return binary.BigEndian.Uint32(data[:])
}

// DecodeUint64 decodes an 8-byte big-endian array to a uint64 value.
//
// Example:
//
//	value := data.DecodeUint64([8]byte{0, 0, 0, 0, 7, 91, 205, 21})
//	// value = 123456789
func DecodeUint64(data [8]byte) uint64 {
	return binary.BigEndian.Uint64(data[:])
}

// DecodeInt16 decodes a 2-byte big-endian array to an int16 value.
//
// Example:
//
//	value := data.DecodeInt16([2]byte{251, 46})
//	// value = -1234
func DecodeInt16(data [2]byte) int16 {
	return int16(DecodeUint16(data))
}

// DecodeInt32 decodes a 4-byte big-endian array to an int32 value.
//
// Example:
//
//	value := data.DecodeInt32([4]byte{255, 254, 29, 192})
//	// value = -123456
func DecodeInt32(data [4]byte) int32 {
	return int32(DecodeUint32(data))
}

// DecodeInt64 decodes an 8-byte big-endian array to an int64 value.
//
// Example:
//
//	value := data.DecodeInt64([8]byte{255, 255, 255, 255, 248, 164, 50, 235})
//	// value = -123456789
func DecodeInt64(data [8]byte) int64 {
	return int64(DecodeUint64(data))
}

// EncodeIntN encodes an integer to a variable-length byte slice.
// This is for cases where size checking is needed.
// Use the fixed-size Encode* functions when the size is known at compile time.
//
// Parameters:
//   - value: The integer value to encode (must be non-negative)
//   - size: The number of bytes to use (1-8)
//
// Returns:
//   - []byte: The encoded value as a big-endian byte slice
//   - error: Error if value is negative, size is invalid, or value doesn't fit
//
// Example:
//
//	bytes, err := data.EncodeIntN(1234, 2)
//	// bytes = [4, 210], err = nil
func EncodeIntN(value int, size int) ([]byte, error) {
	if value < 0 {
		return nil, oops.Errorf("cannot encode negative value: %d", value)
	}

	if size < 1 || size > 8 {
		return nil, oops.Errorf("invalid size: %d (must be 1-8)", size)
	}

	// Check if value fits in the specified size
	var maxValue uint64
	if size >= 8 {
		maxValue = ^uint64(0) // math.MaxUint64
	} else {
		maxValue = uint64(1<<(size*8)) - 1
	}
	if uint64(value) > maxValue {
		return nil, oops.Errorf("value %d exceeds maximum for %d bytes (max: %d)", value, size, maxValue)
	}

	// Encode as uint64 first, then extract the rightmost bytes
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(value))

	// Return only the requested number of bytes from the end
	result := make([]byte, size)
	copy(result, buf[8-size:])
	return result, nil
}

// DecodeIntN decodes a variable-length byte slice to an integer.
//
// Parameters:
//   - data: The byte slice to decode (1-8 bytes, big-endian)
//
// Returns:
//   - int: The decoded integer value
//   - error: Error if data is empty or too large
//
// Example:
//
//	value, err := data.DecodeIntN([]byte{4, 210})
//	// value = 1234, err = nil
func DecodeIntN(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, oops.Errorf("cannot decode empty byte slice")
	}

	if len(data) > 8 {
		return 0, oops.Errorf("byte slice too large: %d bytes (max: 8)", len(data))
	}

	// Pad with zeros on the left to make 8 bytes
	var buf [8]byte
	copy(buf[8-len(data):], data)

	value := binary.BigEndian.Uint64(buf[:])

	// Check if value fits in int
	if value > uint64(^uint(0)>>1) {
		return 0, oops.Errorf("value %d exceeds maximum int", value)
	}

	return int(value), nil
}
