package session_tag

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECIESSessionTag_RejectsWrongSize(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "32 bytes (ElGamal size)",
			data: make([]byte, 32),
		},
		{
			name: "0 bytes",
			data: []byte{},
		},
		{
			name: "7 bytes (one short)",
			data: make([]byte, 7),
		},
		{
			name: "9 bytes (one extra)",
			data: make([]byte, 9),
		},
		{
			name: "1 byte",
			data: []byte{0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewECIESSessionTagFromBytes(tt.data)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid data length")
		})
	}
}

func TestReadECIESSessionTag_NilInput(t *testing.T) {
	_, _, err := ReadECIESSessionTag(nil)
	assert.Error(t, err)
}

func TestNewECIESSessionTag_NilInput(t *testing.T) {
	st, _, err := NewECIESSessionTag(nil)
	assert.Error(t, err)
	assert.Nil(t, st)
}

func TestReadECIESSessionTag_ErrorPath_NilRemainder(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "too short", input: make([]byte, 7)},
		{name: "empty", input: []byte{}},
		{name: "nil", input: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, remainder, err := ReadECIESSessionTag(tt.input)
			assert.Error(t, err)
			assert.Nil(t, remainder, "remainder should be nil on error")
		})
	}
}

func TestReadECIESSessionTag_DirectCopy(t *testing.T) {
	t.Run("valid data with remainder", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xAA, 0xBB}
		tag, remainder, err := ReadECIESSessionTag(data)
		assert.NoError(t, err)
		assert.Equal(t, data[:ECIESSessionTagSize], tag.Bytes())
		assert.Equal(t, []byte{0xAA, 0xBB}, remainder)
	})

	t.Run("exact size", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		tag, remainder, err := ReadECIESSessionTag(data)
		assert.NoError(t, err)
		assert.Equal(t, data, tag.Bytes())
		assert.Empty(t, remainder)
	})

	t.Run("too short returns error", func(t *testing.T) {
		_, _, err := ReadECIESSessionTag([]byte{0x01})
		assert.Error(t, err)
	})
}

func TestReadFunctions_StyleConsistency(t *testing.T) {
	// Both ReadSessionTag and ReadECIESSessionTag should behave identically:
	// on success: (tag, remainder, nil)
	// on error: (zero, nil, error)

	t.Run("SessionTag success", func(t *testing.T) {
		data := append(make([]byte, SessionTagSize), 0xFF)
		tag, rem, err := ReadSessionTag(data)
		assert.NoError(t, err)
		assert.Equal(t, SessionTagSize, len(tag.Bytes()))
		assert.Equal(t, []byte{0xFF}, rem)
	})

	t.Run("ECIESSessionTag success", func(t *testing.T) {
		data := append(make([]byte, ECIESSessionTagSize), 0xFF)
		tag, rem, err := ReadECIESSessionTag(data)
		assert.NoError(t, err)
		assert.Equal(t, ECIESSessionTagSize, len(tag.Bytes()))
		assert.Equal(t, []byte{0xFF}, rem)
	})

	t.Run("SessionTag error returns nil remainder", func(t *testing.T) {
		_, rem, err := ReadSessionTag([]byte{0x01})
		assert.Error(t, err)
		assert.Nil(t, rem)
	})

	t.Run("ECIESSessionTag error returns nil remainder", func(t *testing.T) {
		_, rem, err := ReadECIESSessionTag([]byte{0x01})
		assert.Error(t, err)
		assert.Nil(t, rem)
	})
}
