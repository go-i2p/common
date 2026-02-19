package destination

import (
	"testing"
)

// ============================================================================
// Fuzz test for ReadDestination
// ============================================================================

func FuzzDestinationParse(f *testing.F) {
	validData := make([]byte, 391)
	for i := range validData {
		validData[i] = byte(i % 256)
	}
	validData[384] = 0x05
	validData[385] = 0x00
	validData[386] = 0x04
	validData[387] = 0x00
	validData[388] = 0x00
	validData[389] = 0x00
	validData[390] = 0x00

	f.Add(validData)
	f.Add([]byte{})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		dest, _, err := ReadDestination(data)
		if err != nil {
			return
		}
		b, err := dest.Bytes()
		if err != nil {
			return
		}
		dest2, _, err := ReadDestination(b)
		if err != nil {
			t.Fatalf("round-trip failed: parsed OK, serialized OK, but re-parse failed: %v", err)
		}

		_, _ = dest2.Base32Address()
		_, _ = dest2.Base64()
	})
}
