package session_tag

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
