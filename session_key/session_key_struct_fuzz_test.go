package session_key

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ————————————————————————————————————————————————
// Fuzz tests for SessionKey parsing
// Source: session_key_struct.go
// ————————————————————————————————————————————————

func FuzzReadSessionKey(f *testing.F) {
	// Seed corpus
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(make([]byte, 31))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 33))
	f.Add(make([]byte, 64))
	allFF := make([]byte, 32)
	for i := range allFF {
		allFF[i] = 0xFF
	}
	f.Add(allFF)
	randomBytes := make([]byte, 100)
	rand.Read(randomBytes)
	f.Add(randomBytes)

	f.Fuzz(func(t *testing.T, data []byte) {
		sk, remainder, err := ReadSessionKey(data)
		if len(data) < SESSION_KEY_SIZE {
			// Must error for short input
			assert.Error(t, err)
			assert.Equal(t, SessionKey{}, sk)
		} else {
			// Must succeed for sufficient input
			assert.NoError(t, err)
			assert.True(t, bytes.Equal(sk[:], data[:SESSION_KEY_SIZE]))
			assert.Equal(t, len(data)-SESSION_KEY_SIZE, len(remainder))
		}
	})
}
