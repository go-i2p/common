package session_tag

import (
	"bytes"
	"testing"
)

func FuzzReadECIESSessionTag(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 7))
	f.Add(make([]byte, 8))
	f.Add(make([]byte, 16))

	f.Fuzz(func(t *testing.T, data []byte) {
		st, remainder, err := ReadECIESSessionTag(data)
		if len(data) < ECIESSessionTagSize {
			if err == nil {
				t.Fatal("expected error for short data")
			}
			return
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Verify round-trip
		if !bytes.Equal(st.Bytes(), data[:ECIESSessionTagSize]) {
			t.Fatal("bytes mismatch")
		}
		if len(remainder) != len(data)-ECIESSessionTagSize {
			t.Fatal("remainder length mismatch")
		}
	})
}
