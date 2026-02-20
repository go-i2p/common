package session_key

import (
	"bytes"
	"crypto/rand"
	"encoding"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ————————————————————————————————————————————————
// Unit tests for SessionKey struct methods and constructors
// Source: session_key_struct.go
// ————————————————————————————————————————————————

// --- ReadSessionKey ---

func TestReadSessionKey(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expectedError bool
		expectedRem   []byte
	}{
		{
			name:          "valid 32-byte session key",
			input:         append(make([]byte, 32), []byte{0xFF, 0xFE}...),
			expectedError: false,
			expectedRem:   []byte{0xFF, 0xFE},
		},
		{
			name:          "exact 32-byte session key",
			input:         make([]byte, 32),
			expectedError: false,
			expectedRem:   []byte{},
		},
		{
			name:          "data too short",
			input:         make([]byte, 31),
			expectedError: true,
			expectedRem:   []byte{},
		},
		{
			name:          "empty data",
			input:         []byte{},
			expectedError: true,
			expectedRem:   []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionKey, remainder, err := ReadSessionKey(tt.input)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, 32, len(sessionKey))
				assert.Equal(t, tt.expectedRem, remainder)

				// Verify that the session key contains the first 32 bytes of input
				if len(tt.input) >= 32 {
					assert.True(t, bytes.Equal(sessionKey[:], tt.input[:32]))
				}
			}
		})
	}
}

// --- NewSessionKey ---

func TestNewSessionKey(t *testing.T) {
	validData := make([]byte, 40) // 32 + 8 extra bytes
	for i := range validData {
		validData[i] = byte(i)
	}

	sessionKey, remainder, err := NewSessionKey(validData)
	assert.NoError(t, err)
	assert.NotNil(t, sessionKey)
	assert.Equal(t, 32, len(*sessionKey))
	assert.Equal(t, 8, len(remainder))

	// Test error case
	shortData := make([]byte, 20)
	sessionKey, remainder, err = NewSessionKey(shortData)
	assert.Error(t, err)
	assert.Nil(t, sessionKey)
}

// --- Bytes ---

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

// --- Equal ---

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

// --- String ---

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

// --- SetBytes ---

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

// --- NewSessionKeyFromArray ---

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

// --- IsZero ---

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

// --- GenerateSessionKey ---

func TestGenerateSessionKey(t *testing.T) {
	t.Run("returns 32-byte non-zero key", func(t *testing.T) {
		sk, err := GenerateSessionKey()
		require.NoError(t, err)
		assert.False(t, sk.IsZero(), "generated key should not be all zeros")
	})

	t.Run("two generated keys differ", func(t *testing.T) {
		sk1, err := GenerateSessionKey()
		require.NoError(t, err)
		sk2, err := GenerateSessionKey()
		require.NoError(t, err)
		assert.False(t, sk1.Equal(sk2), "two random keys should differ")
	})

	t.Run("generated key round-trips through ReadSessionKey", func(t *testing.T) {
		sk, err := GenerateSessionKey()
		require.NoError(t, err)

		sk2, remainder, err := ReadSessionKey(sk.Bytes())
		require.NoError(t, err)
		assert.Equal(t, 0, len(remainder))
		assert.True(t, sk.Equal(sk2))
	})

	t.Run("generated key round-trips through MarshalBinary", func(t *testing.T) {
		sk, err := GenerateSessionKey()
		require.NoError(t, err)

		data, err := sk.MarshalBinary()
		require.NoError(t, err)

		var sk2 SessionKey
		err = sk2.UnmarshalBinary(data)
		require.NoError(t, err)
		assert.True(t, sk.Equal(sk2))
	})
}

// --- Zeroize ---

func TestSessionKeyZeroize(t *testing.T) {
	t.Run("zeroize clears key material", func(t *testing.T) {
		sk, err := GenerateSessionKey()
		require.NoError(t, err)
		assert.False(t, sk.IsZero())

		sk.Zeroize()
		assert.True(t, sk.IsZero(), "key should be all zeros after Zeroize()")
	})

	t.Run("zeroize on already-zero key is safe", func(t *testing.T) {
		var sk SessionKey
		assert.True(t, sk.IsZero())
		sk.Zeroize()
		assert.True(t, sk.IsZero())
	})

	t.Run("zeroize clears all bytes", func(t *testing.T) {
		var sk SessionKey
		for i := range sk {
			sk[i] = 0xFF
		}
		sk.Zeroize()
		for i, b := range sk {
			assert.Equal(t, byte(0), b, "byte %d should be zero after Zeroize()", i)
		}
	})
}

// --- MarshalBinary / UnmarshalBinary ---

func TestSessionKeyBinaryMarshaler(t *testing.T) {
	// Verify interface compliance at compile time
	var _ encoding.BinaryMarshaler = SessionKey{}
	var _ encoding.BinaryUnmarshaler = &SessionKey{}

	t.Run("marshal returns defensive copy", func(t *testing.T) {
		var sk SessionKey
		for i := range sk {
			sk[i] = byte(i + 1)
		}
		data, err := sk.MarshalBinary()
		require.NoError(t, err)
		assert.Equal(t, SESSION_KEY_SIZE, len(data))
		assert.True(t, bytes.Equal(sk[:], data))

		// Mutating marshaled data should not affect original
		data[0] = 0xFF
		assert.Equal(t, byte(1), sk[0])
	})

	t.Run("unmarshal valid data", func(t *testing.T) {
		data := make([]byte, SESSION_KEY_SIZE)
		_, err := rand.Read(data)
		require.NoError(t, err)

		var sk SessionKey
		err = sk.UnmarshalBinary(data)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(sk[:], data))
	})

	t.Run("round-trip marshal/unmarshal", func(t *testing.T) {
		sk, err := GenerateSessionKey()
		require.NoError(t, err)

		data, err := sk.MarshalBinary()
		require.NoError(t, err)

		var sk2 SessionKey
		err = sk2.UnmarshalBinary(data)
		require.NoError(t, err)
		assert.True(t, sk.Equal(sk2))
	})

	t.Run("zero key round-trip", func(t *testing.T) {
		var sk SessionKey
		data, err := sk.MarshalBinary()
		require.NoError(t, err)
		assert.Equal(t, make([]byte, SESSION_KEY_SIZE), data)

		var sk2 SessionKey
		err = sk2.UnmarshalBinary(data)
		require.NoError(t, err)
		assert.True(t, sk.Equal(sk2))
	})
}

// --- Bytes() aliasing behavior ---

func TestSessionKeyBytesAliasing(t *testing.T) {
	t.Run("value receiver returns copy not alias", func(t *testing.T) {
		var sk SessionKey
		for i := range sk {
			sk[i] = byte(i + 1)
		}

		b := sk.Bytes()
		original := make([]byte, SESSION_KEY_SIZE)
		copy(original, sk[:])

		b[0] = 0xFF
		// Value receiver means sk was copied; b aliases the copy's memory.
		assert.Equal(t, original[0], sk[0],
			"Bytes() uses value receiver, so mutations to returned slice should not affect original")
	})

	t.Run("Bytes returns correct content", func(t *testing.T) {
		var sk SessionKey
		for i := range sk {
			sk[i] = byte(i * 2)
		}
		b := sk.Bytes()
		for i := 0; i < SESSION_KEY_SIZE; i++ {
			assert.Equal(t, byte(i*2), b[i])
		}
	})

	t.Run("pointer receiver still copies via value receiver", func(t *testing.T) {
		var sk SessionKey
		for i := range sk {
			sk[i] = byte(i + 1)
		}

		ptr := &sk
		b := ptr.Bytes() // still value receiver, so still a copy
		b[0] = 0xFF
		assert.Equal(t, byte(1), sk[0],
			"value receiver Bytes() should not alias even through pointer")
	})
}
