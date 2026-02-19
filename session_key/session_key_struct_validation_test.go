package session_key

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ————————————————————————————————————————————————
// Validation tests for error paths and edge cases
// Source: session_key_struct.go
// ————————————————————————————————————————————————

func TestSessionKeySetBytesErrors(t *testing.T) {
	t.Run("too short input", func(t *testing.T) {
		var sk SessionKey
		err := sk.SetBytes(make([]byte, 31))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid data length")
	})

	t.Run("too long input", func(t *testing.T) {
		var sk SessionKey
		err := sk.SetBytes(make([]byte, 33))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid data length")
	})

	t.Run("empty input", func(t *testing.T) {
		var sk SessionKey
		err := sk.SetBytes([]byte{})
		assert.Error(t, err)
	})

	t.Run("nil input", func(t *testing.T) {
		var sk SessionKey
		err := sk.SetBytes(nil)
		assert.Error(t, err)
	})
}

func TestReadSessionKeyNilInput(t *testing.T) {
	sk, remainder, err := ReadSessionKey(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "data too short")
	assert.Equal(t, SessionKey{}, sk)
	assert.Nil(t, remainder)
}

func TestNewSessionKeyNilInput(t *testing.T) {
	sk, remainder, err := NewSessionKey(nil)
	assert.Error(t, err)
	assert.Nil(t, sk)
	assert.Nil(t, remainder)
}

func TestReadSessionKeyErrorRemainder(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty input", []byte{}},
		{"1 byte short", make([]byte, 31)},
		{"single byte", []byte{0x42}},
		{"nil input", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sk, remainder, err := ReadSessionKey(tt.input)
			assert.Error(t, err)
			assert.Equal(t, SessionKey{}, sk, "SessionKey should be zero-value on error")
			assert.Nil(t, remainder, "remainder should be nil on error")
		})
	}
}
