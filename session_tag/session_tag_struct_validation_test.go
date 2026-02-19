package session_tag

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionTag_SetBytes(t *testing.T) {
	var st SessionTag

	// Valid set
	validData := make([]byte, SessionTagSize)
	for i := range validData {
		validData[i] = byte(i)
	}
	err := st.SetBytes(validData)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(validData, st.Bytes()))

	// Invalid set (too short)
	err = st.SetBytes([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid data length")

	// Invalid set (too long)
	err = st.SetBytes(make([]byte, SessionTagSize+1))
	assert.Error(t, err)

	// Invalid set (empty)
	err = st.SetBytes([]byte{})
	assert.Error(t, err)
}
