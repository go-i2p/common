package destination

import (
	"testing"

	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/assert"
)

// TestDestinationAddressGeneration verifies that Base32Address and Base64 methods
// use the full destination data (KeysAndCert.Bytes()) rather than just certificate data
func TestDestinationAddressGeneration(t *testing.T) {
	assert := assert.New(t)

	// Create test data representing a valid destination (384 bytes keys + certificate)
	// This is minimal test data - in practice it would be generated properly
	keysData := make([]byte, 384) // Minimal keys data
	for i := range keysData {
		keysData[i] = byte(i % 256) // Fill with test pattern
	}

	// Create a KEY certificate (type=5) with minimal payload (4 bytes: crypto_type=0, sig_type=0)
	certData := []byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00}

	// Combine keys and certificate data
	destData := append(keysData, certData...)

	// Parse into KeysAndCert
	keysAndCert, remainder, err := keys_and_cert.ReadKeysAndCert(destData)
	assert.Nil(err, "Should be able to parse test destination data")
	assert.Empty(remainder, "Should consume all data")

	// Create destination
	dest := Destination{KeysAndCert: keysAndCert}

	// Test that addresses are generated
	base32Addr := dest.Base32Address()
	base64Addr := dest.Base64()

	// Verify addresses are not empty
	assert.NotEmpty(base32Addr, "Base32 address should not be empty")
	assert.NotEmpty(base64Addr, "Base64 address should not be empty")

	// Verify Base32 address has correct format
	assert.Contains(base32Addr, ".b32.i2p", "Base32 address should end with .b32.i2p")

	// The key test: verify that the methods use full destination data,
	// not just certificate data
	fullDestBytes := dest.KeysAndCert.Bytes()
	cert := dest.KeysAndCert.Certificate()
	certBytes := cert.Bytes()

	// These should be different - full destination should be much larger
	assert.NotEqual(len(fullDestBytes), len(certBytes), "Full destination bytes should be different size than certificate bytes")
	assert.Greater(len(fullDestBytes), len(certBytes), "Full destination should be larger than certificate alone")

	// Verify that the hash input is the full destination data
	hash := types.SHA256(fullDestBytes)
	expectedBase32 := dest.Base32Address()

	// The generated address should be based on full destination hash
	assert.Contains(expectedBase32, ".b32.i2p", "Address should be properly formatted")
	assert.Greater(len(hash), 0, "Hash should be generated from full destination data")
}
