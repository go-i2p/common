package session_tag

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadSessionTag(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expectedError bool
		expectedRem   []byte
	}{
		{
			name:          "valid 32-byte session tag",
			input:         append(make([]byte, 32), []byte{0xFF, 0xFE}...),
			expectedError: false,
			expectedRem:   []byte{0xFF, 0xFE},
		},
		{
			name:          "exact 32-byte session tag",
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
			sessionTag, remainder, err := ReadSessionTag(tt.input)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, 32, len(sessionTag.Bytes()))
				assert.Equal(t, tt.expectedRem, remainder)

				// Verify that the session tag contains the first 32 bytes of input
				if len(tt.input) >= 32 {
					assert.True(t, bytes.Equal(sessionTag.Bytes(), tt.input[:32]))
				}
			}
		})
	}
}

func TestNewSessionTag(t *testing.T) {
	validData := make([]byte, 40) // 32 + 8 extra bytes
	for i := range validData {
		validData[i] = byte(i)
	}

	sessionTag, remainder, err := NewSessionTag(validData)
	assert.NoError(t, err)
	assert.NotNil(t, sessionTag)
	assert.Equal(t, 32, len(sessionTag.Bytes()))
	assert.Equal(t, 8, len(remainder))

	// Test error case
	shortData := make([]byte, 20)
	sessionTag, remainder, err = NewSessionTag(shortData)
	assert.Error(t, err)
	assert.Nil(t, sessionTag)
}
