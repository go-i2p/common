package session_key

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadSessionKey(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expectedError bool
		expectedRem   []byte
	}{
		{
			name:          "valid 32-byte session key",
			input:         append(make([]byte, 32), []byte{0xFF, 0xFE}...),
			expectedError: false,
			expectedRem:   []byte{0xFF, 0xFE},
		},
		{
			name:          "exact 32-byte session key",
			input:         make([]byte, 32),
			expectedError: false,
			expectedRem:   []byte{},
		},
		{
			name:          "data too short",
			input:         make([]byte, 31),
			expectedError: true,
			expectedRem:   []byte{},
		},
		{
			name:          "empty data",
			input:         []byte{},
			expectedError: true,
			expectedRem:   []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionKey, remainder, err := ReadSessionKey(tt.input)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, 32, len(sessionKey))
				assert.Equal(t, tt.expectedRem, remainder)

				// Verify that the session key contains the first 32 bytes of input
				if len(tt.input) >= 32 {
					assert.True(t, bytes.Equal(sessionKey[:], tt.input[:32]))
				}
			}
		})
	}
}

func TestNewSessionKey(t *testing.T) {
	validData := make([]byte, 40) // 32 + 8 extra bytes
	for i := range validData {
		validData[i] = byte(i)
	}

	sessionKey, remainder, err := NewSessionKey(validData)
	assert.NoError(t, err)
	assert.NotNil(t, sessionKey)
	assert.Equal(t, 32, len(*sessionKey))
	assert.Equal(t, 8, len(remainder))

	// Test error case
	shortData := make([]byte, 20)
	sessionKey, remainder, err = NewSessionKey(shortData)
	assert.Error(t, err)
	assert.Nil(t, sessionKey)
}
