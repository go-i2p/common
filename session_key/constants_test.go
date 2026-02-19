package session_key

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSessionKeyConstant verifies the SESSION_KEY_SIZE constant matches the I2P spec.
func TestSessionKeyConstant(t *testing.T) {
	assert.Equal(t, 32, SESSION_KEY_SIZE, "SessionKey must be 32 bytes per I2P spec")
}
