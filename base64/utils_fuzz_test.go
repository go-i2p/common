package base64

import (
	"strings"
	"testing"
)

// Fuzz tests for utils.go

func FuzzDecodeString(f *testing.F) {
	f.Add("SGVsbG8=")
	f.Add("~~~~")
	f.Add("-~~-")
	f.Add("")
	f.Add("A")
	f.Add("====")
	f.Add("SGVsbG8+")
	f.Add(strings.Repeat("A", 1000))

	f.Fuzz(func(t *testing.T, s string) {
		result, err := DecodeString(s)
		if err == nil && len(s) > 0 {
			reEncoded := EncodeToString(result)
			reDecoded, err2 := DecodeString(reEncoded)
			if err2 != nil {
				t.Fatalf("re-encoding of valid decode result failed: %v", err2)
			}
			if len(result) != len(reDecoded) {
				t.Fatalf("round-trip data length mismatch: %d vs %d", len(result), len(reDecoded))
			}
		}
	})
}

func FuzzDecodeStringSafe(f *testing.F) {
	f.Add("SGVsbG8=")
	f.Add("")
	f.Add("~~~~")
	f.Add(strings.Repeat("A", 1000))

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = DecodeStringSafe(s)
	})
}

func FuzzEncodeToStringSafe(f *testing.F) {
	f.Add([]byte("Hello"))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xff, 0xff, 0xff})
	f.Add([]byte("The quick brown fox jumps over the lazy dog"))

	f.Fuzz(func(t *testing.T, data []byte) {
		encoded, err := EncodeToStringSafe(data)
		if err != nil {
			// Should only error on empty or oversized input
			if len(data) != 0 && len(data) <= MAX_ENCODE_SIZE {
				t.Fatalf("unexpected error for %d-byte input: %v", len(data), err)
			}
			return
		}
		// If encoding succeeded, verify round-trip
		decoded, err := DecodeString(encoded)
		if err != nil {
			t.Fatalf("failed to decode result of EncodeToStringSafe: %v", err)
		}
		if len(data) != len(decoded) {
			t.Fatalf("round-trip data length mismatch: %d vs %d", len(data), len(decoded))
		}
	})
}

func FuzzDecodeStringNoPadding(f *testing.F) {
	f.Add("SGVsbG8")
	f.Add("~~~~")
	f.Add("")
	f.Add("AAAA")
	f.Add(strings.Repeat("A", 1000))

	f.Fuzz(func(t *testing.T, s string) {
		result, err := DecodeStringNoPadding(s)
		if err == nil && len(s) > 0 {
			reEncoded := EncodeToStringNoPadding(result)
			reDecoded, err2 := DecodeStringNoPadding(reEncoded)
			if err2 != nil {
				t.Fatalf("NoPadding round-trip re-encode failed: %v", err2)
			}
			if len(result) != len(reDecoded) {
				t.Fatalf("NoPadding round-trip data length mismatch: %d vs %d",
					len(result), len(reDecoded))
			}
		}
	})
}

func FuzzDecodeStringStrict(f *testing.F) {
	f.Add("SGVsbG8=")
	f.Add("SGVs\nbG8=")
	f.Add("~~~~")
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = DecodeStringStrict(s)
	})
}
