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
