package data

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewHash tests the NewHash constructor with a 32-byte array.
func TestNewHash(t *testing.T) {
	t.Run("create from 32-byte array", func(t *testing.T) {
		var testBytes [32]byte
		for i := 0; i < 32; i++ {
			testBytes[i] = byte(i)
		}

		h := NewHash(testBytes)
		assert.Equal(t, testBytes, h.Bytes())
		assert.False(t, h.IsZero())
	})

	t.Run("create zero hash", func(t *testing.T) {
		var zeroBytes [32]byte
		h := NewHash(zeroBytes)
		assert.True(t, h.IsZero())
		assert.Equal(t, ZeroHash, h)
	})
}

// TestNewHashFromSlice tests the NewHashFromSlice constructor with validation.
func TestNewHashFromSlice(t *testing.T) {
	t.Run("valid 32 bytes", func(t *testing.T) {
		data := make([]byte, 32)
		for i := 0; i < 32; i++ {
			data[i] = byte(i * 2)
		}

		h, err := NewHashFromSlice(data)
		require.NoError(t, err)
		hashBytes := h.Bytes()
		assert.Equal(t, data, hashBytes[:])
		assert.False(t, h.IsZero())
	})

	t.Run("too short - empty", func(t *testing.T) {
		data := []byte{}
		h, err := NewHashFromSlice(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hash must be 32 bytes, got 0")
		assert.True(t, h.IsZero())
	})

	t.Run("too short - 31 bytes", func(t *testing.T) {
		data := make([]byte, 31)
		h, err := NewHashFromSlice(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hash must be 32 bytes, got 31")
		assert.True(t, h.IsZero())
	})

	t.Run("too long - 33 bytes", func(t *testing.T) {
		data := make([]byte, 33)
		h, err := NewHashFromSlice(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hash must be 32 bytes, got 33")
		assert.True(t, h.IsZero())
	})

	t.Run("too long - 64 bytes", func(t *testing.T) {
		data := make([]byte, 64)
		h, err := NewHashFromSlice(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hash must be 32 bytes, got 64")
		assert.True(t, h.IsZero())
	})

	t.Run("round trip with HashData", func(t *testing.T) {
		original := []byte("test data for hashing")
		h := HashData(original)

		hashBytes := h.Bytes()
		h2, err := NewHashFromSlice(hashBytes[:])
		require.NoError(t, err)
		assert.Equal(t, h, h2)
	})
}

// TestHashIsZero tests the IsZero method.
func TestHashIsZero(t *testing.T) {
	t.Run("zero hash", func(t *testing.T) {
		var h Hash
		assert.True(t, h.IsZero())
		assert.Equal(t, ZeroHash, h)
	})

	t.Run("zero hash created with NewHash", func(t *testing.T) {
		var zeroBytes [32]byte
		h := NewHash(zeroBytes)
		assert.True(t, h.IsZero())
	})

	t.Run("non-zero hash", func(t *testing.T) {
		var testBytes [32]byte
		testBytes[0] = 1
		h := NewHash(testBytes)
		assert.False(t, h.IsZero())
	})

	t.Run("hash of empty data is not zero", func(t *testing.T) {
		h := HashData([]byte{})
		assert.False(t, h.IsZero(), "SHA256 of empty data should not be zero hash")

		expected := sha256.Sum256([]byte{})
		assert.Equal(t, expected, h.Bytes())
	})

	t.Run("hash of actual data is not zero", func(t *testing.T) {
		h := HashData([]byte("test"))
		assert.False(t, h.IsZero())
	})
}

// TestHashEqual tests the Equal method.
func TestHashEqual(t *testing.T) {
	t.Run("identical hashes", func(t *testing.T) {
		var testBytes [32]byte
		for i := 0; i < 32; i++ {
			testBytes[i] = byte(i)
		}

		h1 := NewHash(testBytes)
		h2 := NewHash(testBytes)
		assert.True(t, h1.Equal(h2))
	})

	t.Run("different hashes", func(t *testing.T) {
		var bytes1 [32]byte
		var bytes2 [32]byte
		bytes1[0] = 1
		bytes2[0] = 2

		h1 := NewHash(bytes1)
		h2 := NewHash(bytes2)
		assert.False(t, h1.Equal(h2))
	})

	t.Run("zero hashes are equal", func(t *testing.T) {
		var h1 Hash
		var h2 Hash
		assert.True(t, h1.Equal(h2))
		assert.True(t, h1.Equal(ZeroHash))
	})

	t.Run("hash equals itself", func(t *testing.T) {
		h := HashData([]byte("test data"))
		assert.True(t, h.Equal(h))
	})

	t.Run("hashes of same data are equal", func(t *testing.T) {
		data := []byte("identical input")
		h1 := HashData(data)
		h2 := HashData(data)
		assert.True(t, h1.Equal(h2))
	})
}

// TestHashString tests the String method for debugging output.
func TestHashString(t *testing.T) {
	t.Run("zero hash string", func(t *testing.T) {
		var h Hash
		str := h.String()
		assert.Equal(t, strings.Repeat("00", 32), str)
		assert.Len(t, str, 64) // 32 bytes = 64 hex chars
	})

	t.Run("non-zero hash string", func(t *testing.T) {
		var testBytes [32]byte
		testBytes[0] = 0xff
		testBytes[31] = 0xaa

		h := NewHash(testBytes)
		str := h.String()
		assert.True(t, strings.HasPrefix(str, "ff"))
		assert.True(t, strings.HasSuffix(str, "aa"))
		assert.Len(t, str, 64)
	})

	t.Run("hash of known data", func(t *testing.T) {
		h := HashData([]byte("test"))
		str := h.String()
		assert.Len(t, str, 64)
		for _, c := range str {
			assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
		}
	})
}

// TestReadHash tests the ReadHash function for parsing.
func TestReadHash(t *testing.T) {
	t.Run("valid 32-byte read", func(t *testing.T) {
		data := make([]byte, 32)
		for i := 0; i < 32; i++ {
			data[i] = byte(i)
		}

		h, remaining, err := ReadHash(data)
		require.NoError(t, err)
		hashBytes := h.Bytes()
		assert.Equal(t, data, hashBytes[:])
		assert.Empty(t, remaining)
	})

	t.Run("read with remaining bytes", func(t *testing.T) {
		data := make([]byte, 40)
		for i := 0; i < 40; i++ {
			data[i] = byte(i)
		}

		h, remaining, err := ReadHash(data)
		require.NoError(t, err)
		hashBytes := h.Bytes()
		assert.Equal(t, data[:32], hashBytes[:])
		assert.Len(t, remaining, 8)
		assert.Equal(t, data[32:], remaining)
	})

	t.Run("insufficient data - empty", func(t *testing.T) {
		data := []byte{}
		h, remaining, err := ReadHash(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insufficient data for hash: got 0 bytes, need 32")
		assert.True(t, h.IsZero())
		assert.Empty(t, remaining)
	})

	t.Run("insufficient data - 31 bytes", func(t *testing.T) {
		data := make([]byte, 31)
		h, remaining, err := ReadHash(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insufficient data for hash: got 31 bytes, need 32")
		assert.True(t, h.IsZero())
		assert.Equal(t, data, remaining)
	})

	t.Run("exactly 32 bytes", func(t *testing.T) {
		data := make([]byte, 32)
		for i := 0; i < 32; i++ {
			data[i] = byte(255 - i)
		}

		h, remaining, err := ReadHash(data)
		require.NoError(t, err)
		hashBytes := h.Bytes()
		assert.Equal(t, data, hashBytes[:])
		assert.Empty(t, remaining)
	})

	t.Run("round trip with multiple hashes", func(t *testing.T) {
		hash1Data := make([]byte, 32)
		hash2Data := make([]byte, 32)
		for i := 0; i < 32; i++ {
			hash1Data[i] = byte(i)
			hash2Data[i] = byte(i * 2)
		}

		combined := append(hash1Data, hash2Data...)

		h1, remaining, err := ReadHash(combined)
		require.NoError(t, err)
		h1Bytes := h1.Bytes()
		assert.Equal(t, hash1Data, h1Bytes[:])
		assert.Len(t, remaining, 32)

		h2, remaining, err := ReadHash(remaining)
		require.NoError(t, err)
		h2Bytes := h2.Bytes()
		assert.Equal(t, hash2Data, h2Bytes[:])
		assert.Empty(t, remaining)
	})
}

// TestZeroHashConstant tests the ZeroHash constant.
func TestZeroHashConstant(t *testing.T) {
	t.Run("ZeroHash is all zeros", func(t *testing.T) {
		for i := 0; i < 32; i++ {
			assert.Equal(t, byte(0), ZeroHash[i])
		}
	})

	t.Run("ZeroHash.IsZero() returns true", func(t *testing.T) {
		assert.True(t, ZeroHash.IsZero())
	})

	t.Run("default Hash equals ZeroHash", func(t *testing.T) {
		var h Hash
		assert.Equal(t, ZeroHash, h)
		assert.True(t, h.Equal(ZeroHash))
	})
}

// BenchmarkNewHash benchmarks the NewHash constructor.
func BenchmarkNewHash(b *testing.B) {
	var testBytes [32]byte
	for i := 0; i < 32; i++ {
		testBytes[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewHash(testBytes)
	}
}

// BenchmarkNewHashFromSlice benchmarks the NewHashFromSlice constructor.
func BenchmarkNewHashFromSlice(b *testing.B) {
	data := make([]byte, 32)
	for i := 0; i < 32; i++ {
		data[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewHashFromSlice(data)
	}
}

// BenchmarkHashIsZero benchmarks the IsZero method.
func BenchmarkHashIsZero(b *testing.B) {
	var h Hash
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.IsZero()
	}
}

// BenchmarkHashEqual benchmarks the Equal method.
func BenchmarkHashEqual(b *testing.B) {
	h1 := HashData([]byte("test1"))
	h2 := HashData([]byte("test2"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h1.Equal(h2)
	}
}

// BenchmarkReadHash benchmarks the ReadHash function.
func BenchmarkReadHash(b *testing.B) {
	data := make([]byte, 64)
	for i := 0; i < 64; i++ {
		data[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ReadHash(data)
	}
}
