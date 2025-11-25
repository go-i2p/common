package data

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringReportsCorrectLength(t *testing.T) {
	assert := assert.New(t)

	str_len, err := I2PString([]byte{0x02, 0x00, 0x00}).Length()

	assert.Equal(str_len, 2, "Length() did not report correct length")
	assert.Nil(err, "Length() reported an error on valid string")
}

func TestI2PStringReportsLengthZeroError(t *testing.T) {
	assert := assert.New(t)

	str_len, err := I2PString(make([]byte, 0)).Length()

	assert.Equal(str_len, 0, "Length() reported non-zero length on empty slice")
	if assert.NotNil(err) {
		assert.Equal(err.Error(), "error parsing string: zero length", "correct error message should be returned")
	}
}

func TestI2PStringReportsExtraDataError(t *testing.T) {
	assert := assert.New(t)

	str_len, err := I2PString([]byte{0x01, 0x00, 0x00}).Length()

	assert.Equal(str_len, 1, "Length() reported wrong size when extra data present")
	if assert.NotNil(err) {
		assert.Equal(err.Error(), "string parsing warning: string contains data beyond length", "correct error message should be returned")
	}
}

func TestI2PStringDataReportsLengthZeroError(t *testing.T) {
	assert := assert.New(t)

	str_len, err := I2PString([]byte{0x01}).Length()

	assert.Equal(str_len, 1, "Length() reported wrong size with missing data")
	if assert.NotNil(err) {
		assert.Equal(err.Error(), "string parsing warning: string data is shorter than specified by length", "correct error message should be returned")
	}
}

func TestI2PStringDataReportsExtraDataError(t *testing.T) {
	assert := assert.New(t)

	data, err := I2PString([]byte{0x01, 0x00, 0x01}).Data()
	data_len := len(data)

	assert.Equal(data_len, 0, "Data() should return empty string on string with extra data")
	if assert.NotNil(err) {
		assert.Equal(err.Error(), "string parsing warning: string contains data beyond length", "correct error message should be returned")
	}
}

func TestI2PStringDataEmptyWhenZeroLength(t *testing.T) {
	assert := assert.New(t)

	data, err := I2PString(make([]byte, 0)).Data()

	assert.Equal(len(data), 0, "Data() returned data when none was present:")
	if assert.NotNil(err) {
		assert.Equal(err.Error(), "error parsing string: zero length", "correct error message should be returned")
	}
}

func TestI2PStringDataErrorWhenNonZeroLengthOnly(t *testing.T) {
	assert := assert.New(t)

	data, err := I2PString([]byte{0x01}).Data()

	assert.Equal(len(data), 0, "Data() returned data when only length was present")
	if assert.NotNil(err) {
		assert.Equal(err.Error(), "string parsing warning: string data is shorter than specified by length", "correct error message should be returned")
	}
}

func TestToI2PI2PStringFormatsCorrectly(t *testing.T) {
	assert := assert.New(t)

	i2p_string, err := ToI2PString(string([]byte{0x08, 0x09}))

	assert.Nil(err, "ToI2PString() returned error on valid data")
	assert.Equal(2, int(i2p_string[0]), "ToI2PString() did not prepend the correct length")
	assert.Equal(8, int(i2p_string[1]), "ToI2PString() did not include string")
	assert.Equal(9, int(i2p_string[2]), "ToI2PString() did not include string")
}

func TestToI2PStringReportsOverflows(t *testing.T) {
	assert := assert.New(t)

	i2p_string, err := ToI2PString(string(make([]byte, 256)))

	assert.Equal(len(i2p_string), 0, "ToI2PString() returned data when overflowed")
	if assert.NotNil(err) {
		assert.Equal(err.Error(), "cannot store that much data in I2P string", "correct error message should be returned")
	}

	_, err = ToI2PString(string(make([]byte, 255)))

	assert.Nil(err, "ToI2PString() reported error with acceptable size")
}

func TestReadStringReadsLength(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x01, 0x04, 0x06}
	str, remainder, err := ReadI2PString(bytes)

	assert.Nil(err, "ReadI2PString() returned error reading string with extra data")
	assert.Equal(len(str), 2, "ReadI2PString() did not return correct string length")
	assert.Equal(1, int(str[0]), "ReadI2PString() did not return correct string")
	assert.Equal(4, int(str[1]), "ReadI2PString() did not return correct string")
	assert.Equal(len(remainder), 1, "ReadI2PString() did not return correct remainder length")
	assert.Equal(6, int(remainder[0]), "ReadI2PString() did not return correct remainder")
}

func TestReadI2PStringErrWhenEmptySlice(t *testing.T) {
	assert := assert.New(t)

	bytes := make([]byte, 0)
	_, _, err := ReadI2PString(bytes)

	if assert.NotNil(err) {
		assert.Equal(err.Error(), ErrZeroLength.Error(), "correct error message should be returned")
	}
}

func TestReadI2PStringErrWhenDataTooShort(t *testing.T) {
	assert := assert.New(t)

	short_str := []byte{0x03, 0x01}
	str, remainder, err := ReadI2PString(short_str)

	if assert.NotNil(err) {
		assert.Equal(err.Error(), ErrDataTooShort.Error(), "correct error message should be returned")
	}
	// With the fix, ReadI2PString should return partial data consistently with other parsing functions
	assert.Equal(len(str), 2, "ReadI2PString() should return the available data when too short")
	assert.Equal(3, int(str[0]), "ReadI2PString() should return the correct partial string")
	assert.Equal(1, int(str[1]), "ReadI2PString() should return the correct partial string")
	assert.Equal(len(remainder), 0, "ReadI2PString() should return empty remainder when data is too short")
}

// ============ Tests for New Safe Constructors (Issue #2) ============

func TestNewI2PString(t *testing.T) {
	t.Run("valid string", func(t *testing.T) {
		str, err := NewI2PString("hello")
		require.NoError(t, err)
		require.NotNil(t, str)
		assert.Equal(t, 6, len(str)) // 1 byte length + 5 bytes data
		assert.Equal(t, byte(5), str[0])
		assert.Equal(t, "hello", string(str[1:]))
		assert.True(t, str.IsValid())
	})

	t.Run("empty string", func(t *testing.T) {
		str, err := NewI2PString("")
		require.NoError(t, err)
		require.NotNil(t, str)
		assert.Equal(t, 1, len(str)) // Just the length byte
		assert.Equal(t, byte(0), str[0])
		assert.True(t, str.IsValid())
	})

	t.Run("max length string (255 bytes)", func(t *testing.T) {
		maxStr := strings.Repeat("a", STRING_MAX_SIZE)
		str, err := NewI2PString(maxStr)
		require.NoError(t, err)
		require.NotNil(t, str)
		assert.Equal(t, STRING_MAX_SIZE+1, len(str))
		assert.Equal(t, byte(255), str[0])
		assert.True(t, str.IsValid())
	})

	t.Run("too long string (256 bytes)", func(t *testing.T) {
		tooLongStr := strings.Repeat("a", STRING_MAX_SIZE+1)
		str, err := NewI2PString(tooLongStr)
		require.Error(t, err)
		assert.Nil(t, str)
		assert.Contains(t, err.Error(), "string too long")
		assert.Contains(t, err.Error(), "256")
		assert.Contains(t, err.Error(), "max 255")
	})

	t.Run("unicode string", func(t *testing.T) {
		str, err := NewI2PString("hello 世界")
		require.NoError(t, err)
		require.NotNil(t, str)
		assert.True(t, str.IsValid())
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, "hello 世界", data)
	})
}

func TestNewI2PStringFromBytes(t *testing.T) {
	t.Run("valid bytes", func(t *testing.T) {
		bytes := []byte{0x05, 'h', 'e', 'l', 'l', 'o'}
		str, err := NewI2PStringFromBytes(bytes)
		require.NoError(t, err)
		require.NotNil(t, str)
		assert.Equal(t, 6, len(str))
		assert.Equal(t, byte(5), str[0])
		assert.True(t, str.IsValid())
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, "hello", data)
	})

	t.Run("empty bytes", func(t *testing.T) {
		str, err := NewI2PStringFromBytes([]byte{})
		require.Error(t, err)
		assert.Nil(t, str)
		assert.Contains(t, err.Error(), "I2PString data cannot be empty")
	})

	t.Run("length mismatch - data too short", func(t *testing.T) {
		bytes := []byte{0x05, 'h', 'i'} // Declares 5 bytes, but only has 2
		str, err := NewI2PStringFromBytes(bytes)
		require.Error(t, err)
		assert.Nil(t, str)
		assert.Contains(t, err.Error(), "length mismatch")
		assert.Contains(t, err.Error(), "declared 5, actual 2")
	})

	t.Run("length mismatch - data too long", func(t *testing.T) {
		bytes := []byte{0x02, 'h', 'i', 'x', 'x'} // Declares 2 bytes, but has 4
		str, err := NewI2PStringFromBytes(bytes)
		require.Error(t, err)
		assert.Nil(t, str)
		assert.Contains(t, err.Error(), "length mismatch")
		assert.Contains(t, err.Error(), "declared 2, actual 4")
	})

	t.Run("declared length exceeds max", func(t *testing.T) {
		// Create a byte slice claiming to be 256 bytes (> STRING_MAX_SIZE)
		// Note: This is mostly theoretical since we can't actually create such a valid structure
		bytes := make([]byte, 257)
		bytes[0] = 0xFF // 255 is ok
		str, err := NewI2PStringFromBytes(bytes)
		require.Error(t, err)
		assert.Nil(t, str)
		assert.Contains(t, err.Error(), "length mismatch")
	})

	t.Run("zero length string", func(t *testing.T) {
		bytes := []byte{0x00}
		str, err := NewI2PStringFromBytes(bytes)
		require.NoError(t, err)
		require.NotNil(t, str)
		assert.Equal(t, 1, len(str))
		assert.Equal(t, byte(0), str[0])
		assert.True(t, str.IsValid())
	})

	t.Run("max length string", func(t *testing.T) {
		bytes := make([]byte, STRING_MAX_SIZE+1)
		bytes[0] = byte(STRING_MAX_SIZE)
		for i := 1; i <= STRING_MAX_SIZE; i++ {
			bytes[i] = 'a'
		}
		str, err := NewI2PStringFromBytes(bytes)
		require.NoError(t, err)
		require.NotNil(t, str)
		assert.True(t, str.IsValid())
	})
}

func TestI2PStringIsValid(t *testing.T) {
	t.Run("valid string", func(t *testing.T) {
		str := I2PString([]byte{0x03, 'a', 'b', 'c'})
		assert.True(t, str.IsValid())
	})

	t.Run("empty slice is invalid", func(t *testing.T) {
		str := I2PString([]byte{})
		assert.False(t, str.IsValid())
	})

	t.Run("zero length string is valid", func(t *testing.T) {
		str := I2PString([]byte{0x00})
		assert.True(t, str.IsValid())
	})

	t.Run("data too short is invalid", func(t *testing.T) {
		str := I2PString([]byte{0x05, 'a', 'b'}) // Claims 5 bytes, has 2
		assert.False(t, str.IsValid())
	})

	t.Run("data too long is invalid", func(t *testing.T) {
		str := I2PString([]byte{0x02, 'a', 'b', 'c', 'd'}) // Claims 2 bytes, has 4
		assert.False(t, str.IsValid())
	})

	t.Run("max size string is valid", func(t *testing.T) {
		bytes := make([]byte, STRING_MAX_SIZE+1)
		bytes[0] = byte(STRING_MAX_SIZE)
		str := I2PString(bytes)
		assert.True(t, str.IsValid())
	})

	t.Run("oversized declaration is invalid", func(t *testing.T) {
		// This would require 257 bytes total, which is impossible to construct correctly
		// But we can test that IsValid catches the oversized declaration
		bytes := make([]byte, 257)
		bytes[0] = 0xFF // This would claim 255 bytes (which is ok)
		for i := 1; i < 257; i++ {
			bytes[i] = 'a'
		}
		str := I2PString(bytes)
		assert.False(t, str.IsValid()) // Should be invalid due to length mismatch
	})
}

func TestI2PStringDataSafe(t *testing.T) {
	t.Run("valid string", func(t *testing.T) {
		str := I2PString([]byte{0x05, 'h', 'e', 'l', 'l', 'o'})
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, "hello", data)
	})

	t.Run("empty string", func(t *testing.T) {
		str := I2PString([]byte{0x00})
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, "", data)
	})

	t.Run("invalid structure - empty slice", func(t *testing.T) {
		str := I2PString([]byte{})
		data, err := str.DataSafe()
		require.Error(t, err)
		assert.Equal(t, "", data)
		assert.Contains(t, err.Error(), "invalid I2PString structure")
	})

	t.Run("invalid structure - length mismatch", func(t *testing.T) {
		str := I2PString([]byte{0x05, 'h', 'i'}) // Claims 5, has 2
		data, err := str.DataSafe()
		require.Error(t, err)
		assert.Equal(t, "", data)
		assert.Contains(t, err.Error(), "invalid I2PString structure")
	})

	t.Run("unicode data", func(t *testing.T) {
		original := "hello 世界"
		str, err := NewI2PString(original)
		require.NoError(t, err)
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, original, data)
	})
}

func TestI2PStringRoundTrip(t *testing.T) {
	t.Run("simple string", func(t *testing.T) {
		original := "test string"
		str, err := NewI2PString(original)
		require.NoError(t, err)
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, original, data)
	})

	t.Run("empty string", func(t *testing.T) {
		original := ""
		str, err := NewI2PString(original)
		require.NoError(t, err)
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, original, data)
	})

	t.Run("max length string", func(t *testing.T) {
		original := strings.Repeat("x", STRING_MAX_SIZE)
		str, err := NewI2PString(original)
		require.NoError(t, err)
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, original, data)
	})

	t.Run("bytes round-trip", func(t *testing.T) {
		originalBytes := []byte{0x03, 'a', 'b', 'c'}
		str, err := NewI2PStringFromBytes(originalBytes)
		require.NoError(t, err)
		assert.Equal(t, originalBytes, []byte(str))
	})
}

func TestI2PStringEdgeCases(t *testing.T) {
	t.Run("special characters", func(t *testing.T) {
		special := "!@#$%^&*()_+-={}[]|\\:\";<>?,./"
		str, err := NewI2PString(special)
		require.NoError(t, err)
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, special, data)
	})

	t.Run("null bytes in string", func(t *testing.T) {
		withNull := "hello\x00world"
		str, err := NewI2PString(withNull)
		require.NoError(t, err)
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, withNull, data)
	})

	t.Run("all null bytes", func(t *testing.T) {
		nulls := string([]byte{0x00, 0x00, 0x00})
		str, err := NewI2PString(nulls)
		require.NoError(t, err)
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, nulls, data)
	})
}

func TestI2PStringBackwardCompatibility(t *testing.T) {
	t.Run("ToI2PString still works", func(t *testing.T) {
		str, err := ToI2PString("test")
		require.NoError(t, err)
		assert.True(t, str.IsValid())
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, "test", data)
	})

	t.Run("NewI2PString produces same result as ToI2PString", func(t *testing.T) {
		testStr := "comparison test"
		old, err1 := ToI2PString(testStr)
		new, err2 := NewI2PString(testStr)
		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.Equal(t, old, new)
	})
}
