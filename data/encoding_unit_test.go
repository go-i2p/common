package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeUint16(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
		want  [2]byte
	}{
		{"Zero", 0, [2]byte{0x00, 0x00}},
		{"One", 1, [2]byte{0x00, 0x01}},
		{"Max", 65535, [2]byte{0xFF, 0xFF}},
		{"1234", 1234, [2]byte{0x04, 0xD2}},
		{"256", 256, [2]byte{0x01, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EncodeUint16(tt.value)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestEncodeUint32(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
		want  [4]byte
	}{
		{"Zero", 0, [4]byte{0x00, 0x00, 0x00, 0x00}},
		{"One", 1, [4]byte{0x00, 0x00, 0x00, 0x01}},
		{"Max", 4294967295, [4]byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{"123456", 123456, [4]byte{0x00, 0x01, 0xE2, 0x40}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EncodeUint32(tt.value)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestEncodeUint64(t *testing.T) {
	tests := []struct {
		name  string
		value uint64
		want  [8]byte
	}{
		{"Zero", 0, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"One", 1, [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
		{"123456789", 123456789, [8]byte{0x00, 0x00, 0x00, 0x00, 0x07, 0x5B, 0xCD, 0x15}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EncodeUint64(tt.value)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestDecodeUint16(t *testing.T) {
	tests := []struct {
		name string
		data [2]byte
		want uint16
	}{
		{"Zero", [2]byte{0x00, 0x00}, 0},
		{"One", [2]byte{0x00, 0x01}, 1},
		{"Max", [2]byte{0xFF, 0xFF}, 65535},
		{"1234", [2]byte{0x04, 0xD2}, 1234},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DecodeUint16(tt.data)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestDecodeUint32(t *testing.T) {
	tests := []struct {
		name string
		data [4]byte
		want uint32
	}{
		{"Zero", [4]byte{0x00, 0x00, 0x00, 0x00}, 0},
		{"One", [4]byte{0x00, 0x00, 0x00, 0x01}, 1},
		{"Max", [4]byte{0xFF, 0xFF, 0xFF, 0xFF}, 4294967295},
		{"123456", [4]byte{0x00, 0x01, 0xE2, 0x40}, 123456},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DecodeUint32(tt.data)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	t.Run("Uint16", func(t *testing.T) {
		original := uint16(12345)
		encoded := EncodeUint16(original)
		decoded := DecodeUint16(encoded)
		assert.Equal(t, original, decoded)
	})

	t.Run("Uint32", func(t *testing.T) {
		original := uint32(1234567)
		encoded := EncodeUint32(original)
		decoded := DecodeUint32(encoded)
		assert.Equal(t, original, decoded)
	})

	t.Run("Uint64", func(t *testing.T) {
		original := uint64(12345678901234)
		encoded := EncodeUint64(original)
		decoded := DecodeUint64(encoded)
		assert.Equal(t, original, decoded)
	})
}

func TestEncodeInt16(t *testing.T) {
	tests := []struct {
		name  string
		value int16
		want  [2]byte
	}{
		{"Zero", 0, [2]byte{0x00, 0x00}},
		{"Positive", 1234, [2]byte{0x04, 0xD2}},
		{"Negative", -1234, [2]byte{0xFB, 0x2E}},
		{"MinValue", -32768, [2]byte{0x80, 0x00}},
		{"MaxValue", 32767, [2]byte{0x7F, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EncodeInt16(tt.value)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestDecodeInt16(t *testing.T) {
	tests := []struct {
		name string
		data [2]byte
		want int16
	}{
		{"Zero", [2]byte{0x00, 0x00}, 0},
		{"Positive", [2]byte{0x04, 0xD2}, 1234},
		{"Negative", [2]byte{0xFB, 0x2E}, -1234},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DecodeInt16(tt.data)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestEncodeIntN(t *testing.T) {
	tests := []struct {
		name    string
		value   int
		size    int
		want    []byte
		wantErr bool
	}{
		{"1_byte", 255, 1, []byte{0xFF}, false},
		{"2_bytes", 1234, 2, []byte{0x04, 0xD2}, false},
		{"4_bytes", 123456, 4, []byte{0x00, 0x01, 0xE2, 0x40}, false},
		{"Negative", -1, 1, nil, true},
		{"Too_large", 256, 1, nil, true},
		{"Invalid_size_0", 1, 0, nil, true},
		{"Invalid_size_9", 1, 9, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := EncodeIntN(tt.value, tt.size)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

func TestDecodeIntN(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    int
		wantErr bool
	}{
		{"1_byte", []byte{0xFF}, 255, false},
		{"2_bytes", []byte{0x04, 0xD2}, 1234, false},
		{"4_bytes", []byte{0x00, 0x01, 0xE2, 0x40}, 123456, false},
		{"Empty", []byte{}, 0, true},
		{"Too_large", make([]byte, 9), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeIntN(tt.data)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}
		})
	}
}

func TestEncodeIntN_AllSizes(t *testing.T) {
	value := 42

	for size := 1; size <= 8; size++ {
		t.Run(string(rune('0'+size)), func(t *testing.T) {
			result, err := EncodeIntN(value, size)
			require.NoError(t, err)
			assert.Equal(t, size, len(result))

			// Verify round-trip
			decoded, err := DecodeIntN(result)
			require.NoError(t, err)
			assert.Equal(t, value, decoded)
		})
	}
}

func TestEncodeIntNSize8(t *testing.T) {
	t.Run("size 8 with large value", func(t *testing.T) {
		maxInt := int(^uint(0) >> 1) // math.MaxInt
		result, err := EncodeIntN(maxInt, 8)
		require.NoError(t, err)
		assert.Equal(t, 8, len(result))

		// Verify round-trip
		decoded, err := DecodeIntN(result)
		require.NoError(t, err)
		assert.Equal(t, maxInt, decoded)
	})

	t.Run("size 8 with zero", func(t *testing.T) {
		result, err := EncodeIntN(0, 8)
		require.NoError(t, err)
		assert.Equal(t, 8, len(result))
		assert.Equal(t, make([]byte, 8), result)
	})

	t.Run("size 8 with value 1", func(t *testing.T) {
		result, err := EncodeIntN(1, 8)
		require.NoError(t, err)
		expected := []byte{0, 0, 0, 0, 0, 0, 0, 1}
		assert.Equal(t, expected, result)
	})
}

// Benchmark tests
func BenchmarkEncodeUint16(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = EncodeUint16(1234)
	}
}

func BenchmarkEncodeUint32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = EncodeUint32(123456)
	}
}

func BenchmarkDecodeUint16(b *testing.B) {
	data := [2]byte{0x04, 0xD2}
	for i := 0; i < b.N; i++ {
		_ = DecodeUint16(data)
	}
}

func BenchmarkEncodeIntN(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = EncodeIntN(1234, 2)
	}
}

func BenchmarkDecodeIntN(b *testing.B) {
	data := []byte{0x04, 0xD2}
	for i := 0; i < b.N; i++ {
		_, _ = DecodeIntN(data)
	}
}
