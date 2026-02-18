package base64

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Shared test helpers for the base64 package

// interopTestVectors returns test vectors that exercise I2P-specific character substitutions.
var interopTestVectors = []struct {
	name    string
	raw     []byte
	encoded string
	usesI2P bool
}{
	{"simple ASCII (no substitution)", []byte("Hello"), "SGVsbG8=", false},
	{"all 0xFF bytes trigger ~", []byte{0xff, 0xff, 0xff}, "~~~~", true},
	{"0xFB,0xFF,0xFE triggers both - and ~", []byte{0xfb, 0xff, 0xfe}, "-~~-", true},
	{"single 0xFF byte", []byte{0xff}, "~w==", true},
	{"bytes producing - at position 62", []byte{0xf8}, "-A==", true},
	{"empty input", []byte{}, "", false},
}

// stdBase64Equivalence inputs that only produce chars at positions 0-61.
var stdBase64EquivalenceInputs = [][]byte{
	[]byte("Hello, World!"),
	[]byte("The quick brown fox"),
	{0x00, 0x00, 0x00},
	{0x10, 0x20, 0x30},
}

// assertStdBase64Equiv checks that an input produces the same encoding
// in I2P base64 and standard base64 (when no substitution is needed).
func assertStdBase64Equiv(t *testing.T, input []byte) {
	t.Helper()
	i2pEnc := EncodeToString(input)
	stdEnc := base64.StdEncoding.EncodeToString(input)
	if !strings.ContainsAny(stdEnc, "+/") {
		assert.Equal(t, stdEnc, i2pEnc,
			"should match standard base64 when no substitution needed")
	}
}
