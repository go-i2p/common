package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBeginsWithCorrectWhenTrue(t *testing.T) {
	assert := assert.New(t)

	slice := []byte{0x41}

	assert.Equal(true, beginsWith(slice, 0x41), "beginsWith() did not return true when correct")
}

func TestBeginsWithCorrectWhenFalse(t *testing.T) {
	assert := assert.New(t)

	slice := []byte{0x00}

	assert.Equal(false, beginsWith(slice, 0x41), "beginsWith() did not false when incorrect")
}

func TestBeginsWithCorrectWhenNil(t *testing.T) {
	assert := assert.New(t)

	slice := make([]byte, 0)

	assert.Equal(false, beginsWith(slice, 0x41), "beginsWith() did not return false on empty slice")
}

// TestStopValueReadUsesErrorsIs verifies that stopValueRead matches
// using errors.Is(err, ErrZeroLength) instead of string comparison.
func TestStopValueReadUsesErrorsIs(t *testing.T) {
	t.Run("matches ErrZeroLength sentinel", func(t *testing.T) {
		assert.True(t, stopValueRead(ErrZeroLength),
			"Should match the ErrZeroLength sentinel error")
	})

	t.Run("does not match other errors", func(t *testing.T) {
		assert.False(t, stopValueRead(ErrDataTooShort),
			"Should not match ErrDataTooShort")
		assert.False(t, stopValueRead(ErrDataTooLong),
			"Should not match ErrDataTooLong")
	})
}

// TestWrapErrorsNoNilPrefix verifies WrapErrors does not produce <nil> prefix.
func TestWrapErrorsNoNilPrefix(t *testing.T) {
	t.Run("single error has no nil prefix", func(t *testing.T) {
		errs := []error{ErrZeroLength}
		wrapped := WrapErrors(errs)
		require.NotNil(t, wrapped)
		assert.NotContains(t, wrapped.Error(), "<nil>",
			"WrapErrors should not contain <nil> in output")
	})

	t.Run("multiple errors have no nil prefix", func(t *testing.T) {
		errs := []error{ErrZeroLength, ErrDataTooShort, ErrDataTooLong}
		wrapped := WrapErrors(errs)
		require.NotNil(t, wrapped)
		assert.NotContains(t, wrapped.Error(), "<nil>",
			"WrapErrors should not contain <nil> in output")
		assert.Contains(t, wrapped.Error(), "zero length")
		assert.Contains(t, wrapped.Error(), "shorter than specified")
		assert.Contains(t, wrapped.Error(), "beyond length")
	})

	t.Run("empty errors returns nil", func(t *testing.T) {
		wrapped := WrapErrors(nil)
		assert.Nil(t, wrapped)

		wrapped = WrapErrors([]error{})
		assert.Nil(t, wrapped)
	})
}
