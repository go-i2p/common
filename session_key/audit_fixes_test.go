package session_key

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// GAP: Accessor methods — Bytes(), Equal(), String(), SetBytes()
// =============================================================================

func TestSessionKeyBytes(t *testing.T) {
	t.Run("returns correct slice", func(t *testing.T) {
		var sk SessionKey
		for i := range sk {
			sk[i] = byte(i)
		}
		b := sk.Bytes()
		assert.Equal(t, SESSION_KEY_SIZE, len(b))
		assert.True(t, bytes.Equal(b, sk[:]))
	})

	t.Run("zero key returns zero bytes", func(t *testing.T) {
		var sk SessionKey
		b := sk.Bytes()
		assert.Equal(t, SESSION_KEY_SIZE, len(b))
		assert.Equal(t, make([]byte, SESSION_KEY_SIZE), b)
	})
}

func TestSessionKeyEqual(t *testing.T) {
	t.Run("same keys are equal", func(t *testing.T) {
		var a, b SessionKey
		for i := range a {
			a[i] = byte(i + 1)
		}
		b = a
		assert.True(t, a.Equal(b))
	})

	t.Run("different keys are not equal", func(t *testing.T) {
		var a, b SessionKey
		for i := range a {
			a[i] = byte(i + 1)
		}
		b[0] = 0xFF
		assert.False(t, a.Equal(b))
	})

	t.Run("zero keys are equal", func(t *testing.T) {
		var a, b SessionKey
		assert.True(t, a.Equal(b))
	})

	t.Run("single bit difference detected", func(t *testing.T) {
		var a, b SessionKey
		for i := range a {
			a[i] = 0xAA
			b[i] = 0xAA
		}
		b[SESSION_KEY_SIZE-1] ^= 0x01 // flip one bit
		assert.False(t, a.Equal(b))
	})
}

func TestSessionKeyString(t *testing.T) {
	t.Run("zero key format", func(t *testing.T) {
		var sk SessionKey
		expected := hex.EncodeToString(make([]byte, SESSION_KEY_SIZE))
		assert.Equal(t, expected, sk.String())
	})

	t.Run("non-zero key format", func(t *testing.T) {
		var sk SessionKey
		for i := range sk {
			sk[i] = byte(i)
		}
		expected := hex.EncodeToString(sk[:])
		assert.Equal(t, expected, sk.String())
	})

	t.Run("all-FF key format", func(t *testing.T) {
		var sk SessionKey
		for i := range sk {
			sk[i] = 0xFF
		}
		assert.Equal(t, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", sk.String())
	})
}

func TestSessionKeySetBytes(t *testing.T) {
	t.Run("valid 32-byte input", func(t *testing.T) {
		var sk SessionKey
		data := make([]byte, SESSION_KEY_SIZE)
		for i := range data {
			data[i] = byte(i + 10)
		}
		err := sk.SetBytes(data)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(sk[:], data))
	})

	t.Run("too short input", func(t *testing.T) {
		var sk SessionKey
		err := sk.SetBytes(make([]byte, 31))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid data length")
	})

	t.Run("too long input", func(t *testing.T) {
		var sk SessionKey
		err := sk.SetBytes(make([]byte, 33))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid data length")
	})

	t.Run("empty input", func(t *testing.T) {
		var sk SessionKey
		err := sk.SetBytes([]byte{})
		assert.Error(t, err)
	})

	t.Run("nil input", func(t *testing.T) {
		var sk SessionKey
		err := sk.SetBytes(nil)
		assert.Error(t, err)
	})

	t.Run("copies data defensively", func(t *testing.T) {
		var sk SessionKey
		data := make([]byte, SESSION_KEY_SIZE)
		data[0] = 0x42
		err := sk.SetBytes(data)
		require.NoError(t, err)
		// Mutate the original — the SessionKey should be unaffected
		data[0] = 0xFF
		assert.Equal(t, byte(0x42), sk[0])
	})
}

// =============================================================================
// GAP: NewSessionKeyFromArray constructor
// =============================================================================

func TestNewSessionKeyFromArray(t *testing.T) {
	t.Run("creates from array", func(t *testing.T) {
		var arr [SESSION_KEY_SIZE]byte
		for i := range arr {
			arr[i] = byte(i * 3)
		}
		sk := NewSessionKeyFromArray(arr)
		assert.True(t, bytes.Equal(sk[:], arr[:]))
	})

	t.Run("zero array creates zero key", func(t *testing.T) {
		var arr [SESSION_KEY_SIZE]byte
		sk := NewSessionKeyFromArray(arr)
		assert.True(t, sk.IsZero())
	})

	t.Run("round trip with Bytes", func(t *testing.T) {
		var arr [SESSION_KEY_SIZE]byte
		for i := range arr {
			arr[i] = byte(0xDE)
		}
		sk := NewSessionKeyFromArray(arr)
		assert.True(t, bytes.Equal(sk.Bytes(), arr[:]))
	})
}

// =============================================================================
// GAP: IsZero method
// =============================================================================

func TestSessionKeyIsZero(t *testing.T) {
	t.Run("zero key is zero", func(t *testing.T) {
		var sk SessionKey
		assert.True(t, sk.IsZero())
	})

	t.Run("non-zero key is not zero", func(t *testing.T) {
		var sk SessionKey
		sk[0] = 1
		assert.False(t, sk.IsZero())
	})

	t.Run("all-FF key is not zero", func(t *testing.T) {
		var sk SessionKey
		for i := range sk {
			sk[i] = 0xFF
		}
		assert.False(t, sk.IsZero())
	})

	t.Run("last byte non-zero", func(t *testing.T) {
		var sk SessionKey
		sk[SESSION_KEY_SIZE-1] = 0x01
		assert.False(t, sk.IsZero())
	})
}

// =============================================================================
// TEST: Nil input
// =============================================================================

func TestReadSessionKeyNilInput(t *testing.T) {
	sk, remainder, err := ReadSessionKey(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "data too short")
	assert.Equal(t, SessionKey{}, sk)
	assert.Nil(t, remainder)
}

func TestNewSessionKeyNilInput(t *testing.T) {
	sk, remainder, err := NewSessionKey(nil)
	assert.Error(t, err)
	assert.Nil(t, sk)
	assert.Nil(t, remainder)
}

// =============================================================================
// TEST: Round-trip serialization
// =============================================================================

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

// =============================================================================
// TEST: Non-trivial byte patterns
// =============================================================================

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

// =============================================================================
// TEST: Remainder verified in error cases
// =============================================================================

func TestReadSessionKeyErrorRemainder(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty input", []byte{}},
		{"1 byte short", make([]byte, 31)},
		{"single byte", []byte{0x42}},
		{"nil input", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sk, remainder, err := ReadSessionKey(tt.input)
			assert.Error(t, err)
			assert.Equal(t, SessionKey{}, sk, "SessionKey should be zero-value on error")
			assert.Nil(t, remainder, "remainder should be nil on error")
		})
	}
}

// =============================================================================
// TEST: Fuzz test for ReadSessionKey
// =============================================================================

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
