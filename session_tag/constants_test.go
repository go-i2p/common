package session_tag

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionTagSizeConstant(t *testing.T) {
	assert.Equal(t, 32, SessionTagSize, "SessionTagSize should be 32 bytes per I2P spec")
}

func TestECIESSessionTagSizeConstant(t *testing.T) {
	assert.Equal(t, 8, ECIESSessionTagSize, "ECIESSessionTagSize should be 8 bytes per ECIES spec")
}
