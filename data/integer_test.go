package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntegerBigEndian(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	integer := Integer(bytes)

	assert.Equal(integer.Int(), 1, "Integer() did not parse bytes big endian")
}

func TestWorksWithOneByte(t *testing.T) {
	assert := assert.New(t)

	integer := Integer([]byte{0x01})

	assert.Equal(integer.Int(), 1, "Integer() did not correctly parse single byte slice")
}

func TestIsZeroWithNoData(t *testing.T) {
	assert := assert.New(t)

	integer := Integer([]byte{})

	assert.Equal(integer.Int(), 0, "Integer() did not correctly parse zero length byte slice")
}

func TestNewIntegerFromIntValidValues(t *testing.T) {
	assert := assert.New(t)

	// Test valid values for different sizes
	testCases := []struct {
		value       int
		size        int
		expectedInt int
		description string
	}{
		{0, 1, 0, "zero value in 1 byte"},
		{255, 1, 255, "maximum 1-byte value"},
		{256, 2, 256, "value requiring 2 bytes"},
		{65535, 2, 65535, "maximum 2-byte value"},
		{65536, 4, 65536, "value requiring 4 bytes"},
		{1, 8, 1, "small value in 8 bytes"},
	}

	for _, tc := range testCases {
		integer, err := NewIntegerFromInt(tc.value, tc.size)
		assert.Nil(err, "NewIntegerFromInt should not error for %s", tc.description)
		if assert.NotNil(integer, "NewIntegerFromInt should return integer for %s", tc.description) {
			assert.Equal(tc.expectedInt, integer.Int(), "NewIntegerFromInt should return correct value for %s", tc.description)
			assert.Equal(tc.size, len(integer.Bytes()), "NewIntegerFromInt should return correct size for %s", tc.description)
		}
	}
}

func TestNewIntegerFromIntOverflowValidation(t *testing.T) {
	assert := assert.New(t)

	// Test overflow conditions
	testCases := []struct {
		value       int
		size        int
		description string
	}{
		{256, 1, "value 256 in 1 byte (max 255)"},
		{65536, 2, "value 65536 in 2 bytes (max 65535)"},
		{16777216, 3, "value 16777216 in 3 bytes (max 16777215)"},
	}

	for _, tc := range testCases {
		integer, err := NewIntegerFromInt(tc.value, tc.size)
		assert.NotNil(err, "NewIntegerFromInt should error for %s", tc.description)
		assert.Nil(integer, "NewIntegerFromInt should return nil integer for %s", tc.description)
		assert.Contains(err.Error(), "exceeds maximum", "Error should mention exceeding maximum for %s", tc.description)
	}
}

func TestNewIntegerFromIntNegativeValue(t *testing.T) {
	assert := assert.New(t)

	integer, err := NewIntegerFromInt(-1, 4)
	assert.NotNil(err, "NewIntegerFromInt should error for negative values")
	assert.Nil(integer, "NewIntegerFromInt should return nil integer for negative values")
	assert.Contains(err.Error(), "negative value", "Error should mention negative value")
}
