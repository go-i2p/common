package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		bytes := make([]byte, 257)
		bytes[0] = 0xFF
		for i := 1; i < 257; i++ {
			bytes[i] = 'a'
		}
		str := I2PString(bytes)
		assert.False(t, str.IsValid())
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

// TestVerifyI2PStringLengthActualCheck verifies that verifyI2PStringLength
// compares the actual byte count of the string data.
func TestVerifyI2PStringLengthActualCheck(t *testing.T) {
	t.Run("valid string passes verification", func(t *testing.T) {
		str := I2PString([]byte{0x05, 'h', 'e', 'l', 'l', 'o'})
		err := verifyI2PStringLength(str, 5)
		assert.NoError(t, err)
	})

	t.Run("truncated string fails verification", func(t *testing.T) {
		str := I2PString([]byte{0x05, 'h', 'e', 'l'})
		err := verifyI2PStringLength(str, 5)
		assert.ErrorIs(t, err, ErrLengthMismatch,
			"Should detect mismatch between actual data (3 bytes) and expected (5)")
	})

	t.Run("extra data fails verification", func(t *testing.T) {
		str := I2PString([]byte{0x02, 'a', 'b', 'c', 'd'})
		err := verifyI2PStringLength(str, 2)
		assert.ErrorIs(t, err, ErrLengthMismatch,
			"Should detect mismatch between actual data (4 bytes) and expected (2)")
	})

	t.Run("empty string with zero length", func(t *testing.T) {
		str := I2PString([]byte{0x00})
		err := verifyI2PStringLength(str, 0)
		assert.NoError(t, err, "Empty string with matching zero length should pass")
	})

	t.Run("empty input fails", func(t *testing.T) {
		str := I2PString([]byte{})
		err := verifyI2PStringLength(str, 0)
		assert.ErrorIs(t, err, ErrZeroLength)
	})
}
