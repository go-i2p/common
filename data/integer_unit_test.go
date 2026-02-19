package data

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	value, err := intFromBytes(integer.Bytes())
	assert.Equal(0, value, "intFromBytes should return 0 for empty slice")
	assert.NotNil(err, "intFromBytes should return error for empty slice")
	assert.Contains(err.Error(), "empty input slice", "Error should mention empty input slice")

	assert.Equal(0, integer.Int(), "Integer.Int() should return 0 for empty slice")
}

func TestNewIntegerFromIntValidValues(t *testing.T) {
	assert := assert.New(t)

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

// TestNewIntegerFromBytes tests the NewIntegerFromBytes constructor
func TestNewIntegerFromBytes(t *testing.T) {
	assert := assert.New(t)

	t.Run("valid input", func(t *testing.T) {
		bytes := []byte{0x01, 0x02, 0x03, 0x04}
		integer, err := NewIntegerFromBytes(bytes)
		assert.Nil(err, "NewIntegerFromBytes should not error for valid input")
		assert.NotNil(integer, "NewIntegerFromBytes should return integer")
		assert.Equal(bytes, []byte(integer), "NewIntegerFromBytes should preserve bytes")
		assert.Equal(4, len(integer), "NewIntegerFromBytes should preserve length")
	})

	t.Run("empty input", func(t *testing.T) {
		integer, err := NewIntegerFromBytes([]byte{})
		assert.NotNil(err, "NewIntegerFromBytes should error for empty input")
		assert.Nil(integer, "NewIntegerFromBytes should return nil for empty input")
		assert.Contains(err.Error(), "cannot be empty", "Error should mention empty input")
	})

	t.Run("too large", func(t *testing.T) {
		bytes := make([]byte, MAX_INTEGER_SIZE+1)
		integer, err := NewIntegerFromBytes(bytes)
		assert.NotNil(err, "NewIntegerFromBytes should error for oversized input")
		assert.Nil(integer, "NewIntegerFromBytes should return nil for oversized input")
		assert.Contains(err.Error(), "too large", "Error should mention size limit")
	})

	t.Run("max size allowed", func(t *testing.T) {
		bytes := make([]byte, MAX_INTEGER_SIZE)
		bytes[MAX_INTEGER_SIZE-1] = 0x01
		integer, err := NewIntegerFromBytes(bytes)
		assert.Nil(err, "NewIntegerFromBytes should not error for max size")
		assert.NotNil(integer, "NewIntegerFromBytes should return integer for max size")
		assert.Equal(MAX_INTEGER_SIZE, len(integer), "Integer should have max size")
	})

	t.Run("single byte", func(t *testing.T) {
		bytes := []byte{0xFF}
		integer, err := NewIntegerFromBytes(bytes)
		assert.Nil(err, "NewIntegerFromBytes should not error for single byte")
		assert.Equal(255, integer.Int(), "Integer should convert to correct value")
	})

	t.Run("data independence", func(t *testing.T) {
		original := []byte{0x01, 0x02}
		integer, err := NewIntegerFromBytes(original)
		assert.Nil(err)
		original[0] = 0xFF
		assert.Equal(byte(0x01), integer[0], "NewIntegerFromBytes should create independent copy")
	})
}

// TestIntSafe tests the IntSafe method
func TestIntSafe(t *testing.T) {
	assert := assert.New(t)

	t.Run("valid integer", func(t *testing.T) {
		bytes := []byte{0x00, 0x00, 0x00, 0x01}
		integer := Integer(bytes)
		value, err := integer.IntSafe()
		assert.Nil(err, "IntSafe should not error for valid integer")
		assert.Equal(1, value, "IntSafe should return correct value")
	})

	t.Run("empty integer", func(t *testing.T) {
		integer := Integer([]byte{})
		value, err := integer.IntSafe()
		assert.NotNil(err, "IntSafe should error for empty integer")
		assert.Equal(0, value, "IntSafe should return 0 on error")
		assert.Contains(err.Error(), "empty", "Error should mention empty integer")
	})

	t.Run("too large integer", func(t *testing.T) {
		bytes := make([]byte, MAX_INTEGER_SIZE+1)
		integer := Integer(bytes)
		value, err := integer.IntSafe()
		assert.NotNil(err, "IntSafe should error for oversized integer")
		assert.Equal(0, value, "IntSafe should return 0 on error")
		assert.Contains(err.Error(), "too large", "Error should mention size limit")
	})

	t.Run("round trip", func(t *testing.T) {
		originalValue := 42
		integer, err := NewIntegerFromInt(originalValue, 1)
		assert.Nil(err)
		assert.NotNil(integer)

		value, err := integer.IntSafe()
		assert.Nil(err, "IntSafe should not error for valid integer")
		assert.Equal(originalValue, value, "IntSafe should preserve value in round trip")
	})

	t.Run("large value", func(t *testing.T) {
		bytes := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}
		integer := Integer(bytes)
		value, err := integer.IntSafe()
		assert.Nil(err, "IntSafe should not error for 8-byte integer")
		assert.Equal(65536, value, "IntSafe should handle large values correctly")
	})

	t.Run("comparison with Int method", func(t *testing.T) {
		bytes := []byte{0x00, 0xFF}
		integer := Integer(bytes)

		safeValue, err := integer.IntSafe()
		unsafeValue := integer.Int()

		assert.Nil(err, "IntSafe should not error for valid integer")
		assert.Equal(unsafeValue, safeValue, "IntSafe and Int should return same value for valid input")
	})

	t.Run("empty integer unsafe vs safe", func(t *testing.T) {
		integer := Integer([]byte{})

		unsafeValue := integer.Int()
		assert.Equal(0, unsafeValue, "Int() should return 0 for empty")

		safeValue, err := integer.IntSafe()
		assert.NotNil(err, "IntSafe() should error for empty")
		assert.Equal(0, safeValue, "IntSafe() should return 0 on error")
	})
}

// TestIsZero tests the IsZero method
func TestIsZero(t *testing.T) {
	assert := assert.New(t)

	t.Run("zero integer single byte", func(t *testing.T) {
		integer := Integer([]byte{0x00})
		assert.True(integer.IsZero(), "IsZero should return true for zero byte")
	})

	t.Run("zero integer multiple bytes", func(t *testing.T) {
		integer := Integer([]byte{0x00, 0x00, 0x00, 0x00})
		assert.True(integer.IsZero(), "IsZero should return true for all zero bytes")
	})

	t.Run("non-zero integer", func(t *testing.T) {
		integer := Integer([]byte{0x00, 0x01})
		assert.False(integer.IsZero(), "IsZero should return false for non-zero integer")
	})

	t.Run("empty integer", func(t *testing.T) {
		integer := Integer([]byte{})
		assert.True(integer.IsZero(), "IsZero should return true for empty integer")
	})

	t.Run("single non-zero byte", func(t *testing.T) {
		integer := Integer([]byte{0x01})
		assert.False(integer.IsZero(), "IsZero should return false for single non-zero byte")
	})

	t.Run("trailing non-zero byte", func(t *testing.T) {
		integer := Integer([]byte{0x00, 0x00, 0x00, 0x01})
		assert.False(integer.IsZero(), "IsZero should return false if any byte is non-zero")
	})

	t.Run("leading non-zero byte", func(t *testing.T) {
		integer := Integer([]byte{0x01, 0x00, 0x00, 0x00})
		assert.False(integer.IsZero(), "IsZero should return false if any byte is non-zero")
	})

	t.Run("all bytes 0xFF", func(t *testing.T) {
		integer := Integer([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		assert.False(integer.IsZero(), "IsZero should return false for all 0xFF")
	})
}

// TestUintSafe verifies that UintSafe correctly handles unsigned values.
func TestUintSafe(t *testing.T) {
	t.Run("small value", func(t *testing.T) {
		i := Integer([]byte{0x00, 0x01})
		val, err := i.UintSafe()
		require.NoError(t, err)
		assert.Equal(t, uint64(1), val)
	})

	t.Run("max uint16", func(t *testing.T) {
		i := Integer([]byte{0xFF, 0xFF})
		val, err := i.UintSafe()
		require.NoError(t, err)
		assert.Equal(t, uint64(65535), val)
	})

	t.Run("value above int63 boundary", func(t *testing.T) {
		i := Integer([]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

		intVal := i.Int()
		assert.True(t, intVal < 0, "Int() should return negative for values >= 2^63")

		uintVal, err := i.UintSafe()
		require.NoError(t, err)
		assert.Equal(t, uint64(1)<<63, uintVal,
			"UintSafe() should correctly return 2^63")
	})

	t.Run("max uint64", func(t *testing.T) {
		i := Integer([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
		val, err := i.UintSafe()
		require.NoError(t, err)
		assert.Equal(t, uint64(0xFFFFFFFFFFFFFFFF), val)
	})

	t.Run("empty integer", func(t *testing.T) {
		i := Integer([]byte{})
		_, err := i.UintSafe()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("too large integer", func(t *testing.T) {
		i := Integer(make([]byte, 9))
		_, err := i.UintSafe()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too large")
	})

	t.Run("consistency with IntSafe for small values", func(t *testing.T) {
		testValues := []byte{0, 1, 127, 255}
		for _, v := range testValues {
			i := Integer([]byte{v})
			intVal, intErr := i.IntSafe()
			uintVal, uintErr := i.UintSafe()
			require.NoError(t, intErr)
			require.NoError(t, uintErr)
			assert.Equal(t, uint64(intVal), uintVal,
				"IntSafe and UintSafe should agree for value %d", v)
		}
	})
}

// TestMappingDataSizeConsistency verifies that the size field in the
// serialized output of Mapping.Data() always matches the actual payload.
func TestMappingDataSizeConsistency(t *testing.T) {
	t.Run("size matches payload for valid mapping", func(t *testing.T) {
		gomap := map[string]string{"key": "val"}
		mapping, err := GoMapToMapping(gomap)
		require.NoError(t, err)

		serialized := mapping.Data()
		require.NotNil(t, serialized)
		require.True(t, len(serialized) >= 2, "Need at least 2 bytes for size field")

		declaredSize := int(binary.BigEndian.Uint16(serialized[:2]))
		actualPayload := len(serialized) - 2

		assert.Equal(t, actualPayload, declaredSize,
			"Declared size (%d) must match actual payload (%d)", declaredSize, actualPayload)
	})

	t.Run("size recalculated after round trip", func(t *testing.T) {
		gomap := map[string]string{"host": "127.0.0.1", "port": "7654"}
		mapping, err := GoMapToMapping(gomap)
		require.NoError(t, err)

		serialized := mapping.Data()
		require.NotNil(t, serialized)

		declaredSize := int(binary.BigEndian.Uint16(serialized[:2]))
		actualPayload := len(serialized) - 2
		assert.Equal(t, actualPayload, declaredSize)

		reparsed, remainder, errs := ReadMapping(serialized)
		assert.Empty(t, errs)
		assert.Empty(t, remainder)
		assert.Equal(t, len(mapping.Values()), len(reparsed.Values()))
	})
}
