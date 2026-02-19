package data

import (
	"testing"
)

// FuzzReadMapping is a fuzz test for ReadMapping.
func FuzzReadMapping(f *testing.F) {
	// Seed corpus with known valid and edge-case inputs
	f.Add([]byte{0x00, 0x00})                                     // empty mapping
	f.Add([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b}) // a=b
	f.Add([]byte{0x00, 0x01})                                     // size=1, insufficient data
	f.Add([]byte{0xFF, 0xFF})                                     // very large size
	f.Add([]byte{0x00})                                           // too short
	f.Add([]byte{})                                               // empty
	f.Add([]byte{
		0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b,
		0x01, 0x63, 0x3d, 0x01, 0x64, 0x3b,
	}) // extra data beyond size

	f.Fuzz(func(t *testing.T, data []byte) {
		// ReadMapping should never panic on any input
		mapping, _, _ := ReadMapping(data)
		// If we got a mapping, Values() should not panic
		_ = mapping.Values()
	})
}
