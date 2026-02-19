package session_key

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ————————————————————————————————————————————————
// Integration tests: round-trips and non-trivial byte patterns
// Source: session_key_struct.go
// ————————————————————————————————————————————————

func TestSessionKeyRoundTrip(t *testing.T) {
	t.Run("ReadSessionKey round-trip", func(t *testing.T) {
		original := make([]byte, SESSION_KEY_SIZE)
		_, err := rand.Read(original)
		require.NoError(t, err)

		sk, _, err := ReadSessionKey(original)
		require.NoError(t, err)

		// Feed the resulting bytes back through ReadSessionKey
		sk2, _, err := ReadSessionKey(sk[:])
		require.NoError(t, err)

		assert.True(t, sk.Equal(sk2))
		assert.True(t, bytes.Equal(sk[:], sk2[:]))
	})

	t.Run("NewSessionKey round-trip", func(t *testing.T) {
		original := make([]byte, SESSION_KEY_SIZE+8)
		_, err := rand.Read(original)
		require.NoError(t, err)

		sk1, rem1, err := NewSessionKey(original)
		require.NoError(t, err)
		assert.Equal(t, 8, len(rem1))

		sk2, rem2, err := NewSessionKey(sk1.Bytes())
		require.NoError(t, err)
		assert.Equal(t, 0, len(rem2))
		assert.True(t, sk1.Equal(*sk2))
	})

	t.Run("SetBytes round-trip", func(t *testing.T) {
		data := make([]byte, SESSION_KEY_SIZE)
		_, err := rand.Read(data)
		require.NoError(t, err)

		var sk SessionKey
		err = sk.SetBytes(data)
		require.NoError(t, err)

		var sk2 SessionKey
		err = sk2.SetBytes(sk.Bytes())
		require.NoError(t, err)

		assert.True(t, sk.Equal(sk2))
	})
}

func TestSessionKeyNonTrivialPatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern func() []byte
	}{
		{
			name: "all 0xFF",
			pattern: func() []byte {
				b := make([]byte, SESSION_KEY_SIZE)
				for i := range b {
					b[i] = 0xFF
				}
				return b
			},
		},
		{
			name: "alternating 0xAA/0x55",
			pattern: func() []byte {
				b := make([]byte, SESSION_KEY_SIZE)
				for i := range b {
					if i%2 == 0 {
						b[i] = 0xAA
					} else {
						b[i] = 0x55
					}
				}
				return b
			},
		},
		{
			name: "sequential bytes",
			pattern: func() []byte {
				b := make([]byte, SESSION_KEY_SIZE)
				for i := range b {
					b[i] = byte(i)
				}
				return b
			},
		},
		{
			name: "reverse sequential",
			pattern: func() []byte {
				b := make([]byte, SESSION_KEY_SIZE)
				for i := range b {
					b[i] = byte(SESSION_KEY_SIZE - 1 - i)
				}
				return b
			},
		},
		{
			name: "random bytes",
			pattern: func() []byte {
				b := make([]byte, SESSION_KEY_SIZE)
				rand.Read(b)
				return b
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.pattern()
			sk, remainder, err := ReadSessionKey(data)
			require.NoError(t, err)
			assert.Equal(t, 0, len(remainder))
			assert.True(t, bytes.Equal(sk[:], data))
		})
	}
}
