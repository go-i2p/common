package session_tag

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- SessionTag tests (ported from ECIES equivalents) ---

func TestSessionTag_RoundTrip(t *testing.T) {
	testData := make([]byte, SessionTagSize)
	for i := range testData {
		testData[i] = byte(i + 1)
	}

	st, err := NewSessionTagFromBytes(testData)
	assert.NoError(t, err)

	// Verify Bytes() matches original
	assert.True(t, bytes.Equal(st.Bytes(), testData))

	// Verify Array() matches
	var expectedArray [SessionTagSize]byte
	copy(expectedArray[:], testData)
	assert.Equal(t, expectedArray, st.Array())
}

func TestSessionTag_Equal(t *testing.T) {
	data1 := make([]byte, SessionTagSize)
	data2 := make([]byte, SessionTagSize)
	data3 := make([]byte, SessionTagSize)
	for i := range data1 {
		data1[i] = byte(i)
		data2[i] = byte(i)
		data3[i] = byte(i ^ 0xFF)
	}

	st1, err := NewSessionTagFromBytes(data1)
	assert.NoError(t, err)

	st2, err := NewSessionTagFromBytes(data2)
	assert.NoError(t, err)

	st3, err := NewSessionTagFromBytes(data3)
	assert.NoError(t, err)

	// Same data should be equal
	assert.True(t, st1.Equal(st2))
	assert.True(t, st2.Equal(st1))

	// Different data should not be equal
	assert.False(t, st1.Equal(st3))
	assert.False(t, st3.Equal(st1))

	// Self-equality
	assert.True(t, st1.Equal(st1))
}

func TestSessionTag_String(t *testing.T) {
	data := make([]byte, SessionTagSize)
	data[0] = 0x01
	data[1] = 0x02
	data[2] = 0xAB
	data[SessionTagSize-1] = 0xFF

	st, err := NewSessionTagFromBytes(data)
	assert.NoError(t, err)

	str := st.String()
	// Should start with "0102ab" and end with "ff"
	assert.Contains(t, str, "0102ab")
	assert.Len(t, str, SessionTagSize*2) // hex encoding doubles length
}

func TestSessionTag_SetBytes(t *testing.T) {
	var st SessionTag

	// Valid set
	validData := make([]byte, SessionTagSize)
	for i := range validData {
		validData[i] = byte(i)
	}
	err := st.SetBytes(validData)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(validData, st.Bytes()))

	// Invalid set (too short)
	err = st.SetBytes([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid data length")

	// Invalid set (too long)
	err = st.SetBytes(make([]byte, SessionTagSize+1))
	assert.Error(t, err)

	// Invalid set (empty)
	err = st.SetBytes([]byte{})
	assert.Error(t, err)
}

func TestSessionTag_NewFromBytes(t *testing.T) {
	validData := make([]byte, SessionTagSize)
	for i := range validData {
		validData[i] = byte(i)
	}

	st, err := NewSessionTagFromBytes(validData)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(validData, st.Bytes()))

	// Wrong size
	_, err = NewSessionTagFromBytes(make([]byte, 16))
	assert.Error(t, err)

	// Empty
	_, err = NewSessionTagFromBytes([]byte{})
	assert.Error(t, err)
}

func TestSessionTag_NewFromArray(t *testing.T) {
	var arr [SessionTagSize]byte
	for i := range arr {
		arr[i] = byte(i + 10)
	}

	st := NewSessionTagFromArray(arr)
	assert.Equal(t, arr, st.Array())
	assert.True(t, bytes.Equal(arr[:], st.Bytes()))
}

// --- Nil input tests ---

func TestReadSessionTag_NilInput(t *testing.T) {
	_, _, err := ReadSessionTag(nil)
	assert.Error(t, err)
}

func TestReadECIESSessionTag_NilInput(t *testing.T) {
	_, _, err := ReadECIESSessionTag(nil)
	assert.Error(t, err)
}

func TestNewSessionTag_NilInput(t *testing.T) {
	st, _, err := NewSessionTag(nil)
	assert.Error(t, err)
	assert.Nil(t, st)
}

func TestNewECIESSessionTag_NilInput(t *testing.T) {
	st, _, err := NewECIESSessionTag(nil)
	assert.Error(t, err)
	assert.Nil(t, st)
}

// --- IsZero tests ---

func TestSessionTag_IsZero(t *testing.T) {
	// Default zero value
	var st SessionTag
	assert.True(t, st.IsZero())

	// After setting non-zero data
	data := make([]byte, SessionTagSize)
	data[0] = 0x01
	err := st.SetBytes(data)
	assert.NoError(t, err)
	assert.False(t, st.IsZero())

	// Explicitly zero data
	zeroData := make([]byte, SessionTagSize)
	st2, err := NewSessionTagFromBytes(zeroData)
	assert.NoError(t, err)
	assert.True(t, st2.IsZero())
}

func TestECIESSessionTag_IsZero(t *testing.T) {
	// Default zero value
	var st ECIESSessionTag
	assert.True(t, st.IsZero())

	// After setting non-zero data
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	err := st.SetBytes(data)
	assert.NoError(t, err)
	assert.False(t, st.IsZero())

	// Explicitly zero data
	zeroData := make([]byte, ECIESSessionTagSize)
	st2, err := NewECIESSessionTagFromBytes(zeroData)
	assert.NoError(t, err)
	assert.True(t, st2.IsZero())
}

// --- Fuzz tests ---

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
