package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDateSizeConstant(t *testing.T) {
	assert.Equal(t, 8, DATE_SIZE, "DATE_SIZE should be 8")
}

func TestMaxIntegerSizeConstant(t *testing.T) {
	assert.Equal(t, 8, MAX_INTEGER_SIZE, "MAX_INTEGER_SIZE should be 8")
}

func TestStringMaxSizeConstant(t *testing.T) {
	assert.Equal(t, 255, STRING_MAX_SIZE, "STRING_MAX_SIZE should be 255")
}

func TestMappingDelimiterConstants(t *testing.T) {
	assert.Equal(t, 0x3d, MAPPING_EQUALS_DELIMITER, "MAPPING_EQUALS_DELIMITER should be 0x3d (=)")
	assert.Equal(t, 0x3b, MAPPING_SEMICOLON_DELIMITER, "MAPPING_SEMICOLON_DELIMITER should be 0x3b (;)")
}

func TestKeyValIntegerLengthConstant(t *testing.T) {
	assert.Equal(t, 1, KEY_VAL_INTEGER_LENGTH, "KEY_VAL_INTEGER_LENGTH should be 1")
}

func TestBitsPerByteConstant(t *testing.T) {
	assert.Equal(t, 8, BITS_PER_BYTE, "BITS_PER_BYTE should be 8")
}
