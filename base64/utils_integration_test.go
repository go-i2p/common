package base64

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests for utils.go — interoperability with standard base64

func TestInteropTestVectors(t *testing.T) {
	for _, tt := range interopTestVectors {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeToString(tt.raw)
			assert.Equal(t, tt.encoded, encoded, "encoding mismatch")

			if tt.usesI2P {
				stdEncoded := base64.StdEncoding.EncodeToString(tt.raw)
				assert.NotEqual(t, stdEncoded, encoded,
					"I2P encoding should differ from standard when using substituted chars")
			}

			if len(tt.encoded) > 0 {
				decoded, err := DecodeString(tt.encoded)
				require.NoError(t, err, "decode should succeed")
				assert.Equal(t, tt.raw, decoded, "round-trip decode mismatch")
			}
		})
	}
}

func TestInteropStandardBase64Equivalence(t *testing.T) {
	for _, input := range stdBase64EquivalenceInputs {
		assertStdBase64Equiv(t, input)
	}
}
