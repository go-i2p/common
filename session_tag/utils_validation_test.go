package session_tag

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadSessionTag_NilInput(t *testing.T) {
	_, _, err := ReadSessionTag(nil)
	assert.Error(t, err)
}

func TestNewSessionTag_NilInput(t *testing.T) {
	st, _, err := NewSessionTag(nil)
	assert.Error(t, err)
	assert.Nil(t, st)
}

func TestReadSessionTag_ErrorPath_NilRemainder(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "too short", input: make([]byte, 31)},
		{name: "empty", input: []byte{}},
		{name: "nil", input: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, remainder, err := ReadSessionTag(tt.input)
			assert.Error(t, err)
			assert.Nil(t, remainder, "remainder should be nil on error")
		})
	}
}
