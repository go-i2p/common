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
