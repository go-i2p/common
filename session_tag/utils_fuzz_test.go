package session_tag

import (
	"bytes"
	"testing"
)

func FuzzReadSessionTag(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 31))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		st, remainder, err := ReadSessionTag(data)
		if len(data) < SessionTagSize {
			if err == nil {
				t.Fatal("expected error for short data")
			}
			return
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Verify round-trip
		if !bytes.Equal(st.Bytes(), data[:SessionTagSize]) {
			t.Fatal("bytes mismatch")
		}
		if len(remainder) != len(data)-SessionTagSize {
			t.Fatal("remainder length mismatch")
		}
	})
}
