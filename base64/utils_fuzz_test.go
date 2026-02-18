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
