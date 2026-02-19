package session_tag

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECIESSessionTag_RoundTrip(t *testing.T) {
	// Create test data
	testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Create from bytes
	st, err := NewECIESSessionTagFromBytes(testData)
	assert.NoError(t, err)

	// Verify Bytes() matches original
	assert.True(t, bytes.Equal(st.Bytes(), testData))

	// Verify Array() matches
	expectedArray := [ECIESSessionTagSize]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	assert.Equal(t, expectedArray, st.Array())
}

func TestECIESSessionTag_Equal(t *testing.T) {
	data1 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	data2 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	data3 := []byte{0xFF, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	st1, err := NewECIESSessionTagFromBytes(data1)
	assert.NoError(t, err)

	st2, err := NewECIESSessionTagFromBytes(data2)
	assert.NoError(t, err)

	st3, err := NewECIESSessionTagFromBytes(data3)
	assert.NoError(t, err)

	// Same data should be equal
	assert.True(t, st1.Equal(st2))
	assert.True(t, st2.Equal(st1))

	// Different data should not be equal
	assert.False(t, st1.Equal(st3))
	assert.False(t, st3.Equal(st1))
}

func TestECIESSessionTag_String(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	st, err := NewECIESSessionTagFromBytes(data)
	assert.NoError(t, err)

	// String should be hex representation
	expected := "0102030405060708"
	assert.Equal(t, expected, st.String())
}

func TestECIESSessionTag_FromArray(t *testing.T) {
	arr := [ECIESSessionTagSize]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}

	st := NewECIESSessionTagFromArray(arr)

	assert.Equal(t, arr, st.Array())
	assert.True(t, bytes.Equal(arr[:], st.Bytes()))
}

func TestECIESSessionTag_SetBytes(t *testing.T) {
	var st ECIESSessionTag

	// Valid set
	validData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	err := st.SetBytes(validData)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(validData, st.Bytes()))

	// Invalid set (wrong size)
	invalidData := []byte{0x01, 0x02, 0x03}
	err = st.SetBytes(invalidData)
	assert.Error(t, err)
}

func TestReadECIESSessionTag(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expectedError bool
		expectedRem   []byte
	}{
		{
			name:          "valid 8-byte session tag with remainder",
			input:         []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xFF, 0xFE},
			expectedError: false,
			expectedRem:   []byte{0xFF, 0xFE},
		},
		{
			name:          "exact 8-byte session tag",
			input:         make([]byte, 8),
			expectedError: false,
			expectedRem:   []byte{},
		},
		{
			name:          "data too short",
			input:         make([]byte, 7),
			expectedError: true,
			expectedRem:   nil,
		},
		{
			name:          "empty data",
			input:         []byte{},
			expectedError: true,
			expectedRem:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionTag, remainder, err := ReadECIESSessionTag(tt.input)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, ECIESSessionTagSize, len(sessionTag.Bytes()))
				assert.Equal(t, tt.expectedRem, remainder)

				// Verify that the session tag contains the first 8 bytes of input
				if len(tt.input) >= ECIESSessionTagSize {
					assert.True(t, bytes.Equal(sessionTag.Bytes(), tt.input[:ECIESSessionTagSize]))
				}
			}
		})
	}
}

func TestNewECIESSessionTag(t *testing.T) {
	validData := make([]byte, 16) // 8 + 8 extra bytes
	for i := range validData {
		validData[i] = byte(i)
	}

	sessionTag, remainder, err := NewECIESSessionTag(validData)
	assert.NoError(t, err)
	assert.NotNil(t, sessionTag)
	assert.Equal(t, ECIESSessionTagSize, len(sessionTag.Bytes()))
	assert.Equal(t, 8, len(remainder))

	// Test error case
	shortData := make([]byte, 5)
	sessionTag, remainder, err = NewECIESSessionTag(shortData)
	assert.Error(t, err)
	assert.Nil(t, sessionTag)
}

func TestECIESSessionTag_IsZero(t *testing.T) {
	// Default zero value
	var st ECIESSessionTag
	assert.True(t, st.IsZero())

	// After setting non-zero data
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	err := st.SetBytes(data)
	assert.NoError(t, err)
	assert.False(t, st.IsZero())

	// Explicitly zero data
	zeroData := make([]byte, ECIESSessionTagSize)
	st2, err := NewECIESSessionTagFromBytes(zeroData)
	assert.NoError(t, err)
	assert.True(t, st2.IsZero())
}
