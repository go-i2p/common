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

// FuzzSetBytes verifies that SessionTag.SetBytes only accepts exactly
// SessionTagSize bytes and that the stored value matches the input exactly.
func FuzzSetBytes(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 31))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 33))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		var st SessionTag
		err := st.SetBytes(data)
		if len(data) != SessionTagSize {
			if err == nil {
				t.Fatalf("expected error for len=%d, got nil", len(data))
			}
			return
		}
		if err != nil {
			t.Fatalf("unexpected error for valid length: %v", err)
		}
		if !bytes.Equal(st.Bytes(), data) {
			t.Fatal("stored bytes do not match input")
		}
	})
}

// FuzzNewSessionTagFromBytes verifies that NewSessionTagFromBytes accepts
// only exactly SessionTagSize bytes and that the returned tag matches.
func FuzzNewSessionTagFromBytes(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 31))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 33))

	f.Fuzz(func(t *testing.T, data []byte) {
		st, err := NewSessionTagFromBytes(data)
		if len(data) != SessionTagSize {
			if err == nil {
				t.Fatalf("expected error for len=%d, got nil", len(data))
			}
			return
		}
		if err != nil {
			t.Fatalf("unexpected error for valid length: %v", err)
		}
		if !bytes.Equal(st.Bytes(), data) {
			t.Fatal("returned tag bytes do not match input")
		}
	})
}
