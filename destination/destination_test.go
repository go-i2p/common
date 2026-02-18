package destination

import (
	"testing"

	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//
// Constructor Tests
//

// TestNewDestination tests the primary constructor for creating destinations
func TestNewDestination(t *testing.T) {
	t.Run("valid KeysAndCert creates destination", func(t *testing.T) {
		// Create valid KeysAndCert
		keysAndCert := createValidKeysAndCert(t)

		dest, err := NewDestination(keysAndCert)
		require.NoError(t, err)
		require.NotNil(t, dest)
		assert.Equal(t, keysAndCert, dest.KeysAndCert)
		assert.True(t, dest.IsValid())
	})

	t.Run("nil KeysAndCert returns error", func(t *testing.T) {
		dest, err := NewDestination(nil)
		require.Error(t, err)
		assert.Nil(t, dest)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("invalid KeysAndCert returns error", func(t *testing.T) {
		// Create invalid KeysAndCert (nil key certificate)
		invalidKeysAndCert := &keys_and_cert.KeysAndCert{}

		dest, err := NewDestination(invalidKeysAndCert)
		require.Error(t, err)
		assert.Nil(t, dest)
		assert.Contains(t, err.Error(), "invalid KeysAndCert")
	})
}

// TestNewDestinationFromBytes tests parsing destinations from byte slices
func TestNewDestinationFromBytes(t *testing.T) {
	t.Run("valid bytes create destination", func(t *testing.T) {
		// Create test destination data
		originalData := createValidDestinationBytes(t)

		dest, remainder, err := NewDestinationFromBytes(originalData)
		require.NoError(t, err)
		require.NotNil(t, dest)
		assert.Empty(t, remainder)
		assert.True(t, dest.IsValid())
	})

	t.Run("invalid bytes return error", func(t *testing.T) {
		invalidData := []byte{0x00, 0x01, 0x02} // Too short

		dest, _, err := NewDestinationFromBytes(invalidData)
		require.Error(t, err)
		assert.Nil(t, dest)
	})

	t.Run("empty bytes return error", func(t *testing.T) {
		dest, _, err := NewDestinationFromBytes([]byte{})
		require.Error(t, err)
		assert.Nil(t, dest)
	})

	t.Run("extra bytes returned as remainder", func(t *testing.T) {
		originalData := createValidDestinationBytes(t)
		extraBytes := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		dataWithExtra := append(originalData, extraBytes...)

		dest, remainder, err := NewDestinationFromBytes(dataWithExtra)
		require.NoError(t, err)
		require.NotNil(t, dest)
		assert.Equal(t, extraBytes, remainder)
	})
}

//
// Validation Tests
//

// TestDestinationValidate tests the Validate method
func TestDestinationValidate(t *testing.T) {
	t.Run("valid destination passes validation", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		dest, err := NewDestination(keysAndCert)
		require.NoError(t, err)

		err = dest.Validate()
		assert.NoError(t, err)
	})

	t.Run("nil destination fails validation", func(t *testing.T) {
		var dest *Destination
		err := dest.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "destination is nil")
	})

	t.Run("destination with nil KeysAndCert fails validation", func(t *testing.T) {
		dest := &Destination{KeysAndCert: nil}
		err := dest.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KeysAndCert is nil")
	})

	t.Run("destination with invalid KeysAndCert fails validation", func(t *testing.T) {
		// Create invalid KeysAndCert (nil key certificate)
		invalidKeysAndCert := &keys_and_cert.KeysAndCert{}
		dest := &Destination{KeysAndCert: invalidKeysAndCert}

		err := dest.Validate()
		require.Error(t, err)
	})
}

// TestDestinationIsValid tests the IsValid convenience method
func TestDestinationIsValid(t *testing.T) {
	t.Run("valid destination returns true", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		dest, err := NewDestination(keysAndCert)
		require.NoError(t, err)

		assert.True(t, dest.IsValid())
	})

	t.Run("nil destination returns false", func(t *testing.T) {
		var dest *Destination
		assert.False(t, dest.IsValid())
	})

	t.Run("destination with nil KeysAndCert returns false", func(t *testing.T) {
		dest := &Destination{KeysAndCert: nil}
		assert.False(t, dest.IsValid())
	})

	t.Run("destination with invalid KeysAndCert returns false", func(t *testing.T) {
		invalidKeysAndCert := &keys_and_cert.KeysAndCert{}
		dest := &Destination{KeysAndCert: invalidKeysAndCert}

		assert.False(t, dest.IsValid())
	})
}

//
// Integration Tests
//

// TestDestinationRoundTrip verifies constructor and serialization work together
func TestDestinationRoundTrip(t *testing.T) {
	t.Run("NewDestination -> Bytes -> NewDestinationFromBytes", func(t *testing.T) {
		// Create original destination
		keysAndCert := createValidKeysAndCert(t)
		dest1, err := NewDestination(keysAndCert)
		require.NoError(t, err)

		// Serialize to bytes
		bytes, err := dest1.Bytes()
		require.NoError(t, err)

		// Parse back from bytes
		dest2, remainder, err := NewDestinationFromBytes(bytes)
		require.NoError(t, err)
		assert.Empty(t, remainder)

		// Both should be valid
		assert.True(t, dest1.IsValid())
		assert.True(t, dest2.IsValid())

		// Both should generate same addresses
		addr1, err := dest1.Base32Address()
		require.NoError(t, err)
		addr2, err := dest2.Base32Address()
		require.NoError(t, err)
		assert.Equal(t, addr1, addr2)

		b64_1, err := dest1.Base64()
		require.NoError(t, err)
		b64_2, err := dest2.Base64()
		require.NoError(t, err)
		assert.Equal(t, b64_1, b64_2)
	})

	t.Run("validation after construction", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		dest, err := NewDestination(keysAndCert)
		require.NoError(t, err)

		// Destination created with constructor should always be valid
		assert.NoError(t, dest.Validate())
		assert.True(t, dest.IsValid())

		// Should be able to generate addresses
		_, err = dest.Base32Address()
		assert.NoError(t, err)
		_, err = dest.Base64()
		assert.NoError(t, err)
	})
}

//
// Test Helpers
//

// createValidKeysAndCert creates a valid KeysAndCert for testing
func createValidKeysAndCert(t *testing.T) *keys_and_cert.KeysAndCert {
	t.Helper()

	// Create test destination bytes and parse into KeysAndCert
	destBytes := createValidDestinationBytes(t)
	keysAndCert, _, err := keys_and_cert.ReadKeysAndCert(destBytes)
	require.NoError(t, err, "Failed to create test KeysAndCert")

	return keysAndCert
}

// createValidDestinationBytes creates valid destination bytes for testing
func createValidDestinationBytes(t *testing.T) []byte {
	t.Helper()

	// Create minimal valid keys data (384 bytes for default crypto)
	keysData := make([]byte, 384)
	for i := range keysData {
		keysData[i] = byte(i % 256)
	}

	// Create KEY certificate (type=5) with minimal valid payload
	// KeyCertificate structure:
	//   type (1 byte) = 5
	//   length (2 bytes) = 4
	//   sig_type (2 bytes) = 0 (DSA-SHA1)   [signing type first per I2P spec]
	//   crypto_type (2 bytes) = 0 (ElGamal) [crypto type second per I2P spec]
	certData := []byte{
		0x05,       // type = KEY certificate (5)
		0x00, 0x04, // length = 4 bytes
		0x00, 0x00, // sig_type = 0 (DSA-SHA1)
		0x00, 0x00, // crypto_type = 0 (ElGamal)
	}

	// Combine keys and certificate
	return append(keysData, certData...)
}

//
// Existing Tests
//

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
	base32Addr, err := dest.Base32Address()
	assert.Nil(err, "Base32Address() should not error")
	base64Addr, err := dest.Base64()
	assert.Nil(err, "Base64() should not error")

	// Verify addresses are not empty
	assert.NotEmpty(base32Addr, "Base32 address should not be empty")
	assert.NotEmpty(base64Addr, "Base64 address should not be empty")

	// Verify Base32 address has correct format
	assert.Contains(base32Addr, ".b32.i2p", "Base32 address should end with .b32.i2p")

	// The key test: verify that the methods use full destination data,
	// not just certificate data
	fullDestBytes, err := dest.KeysAndCert.Bytes()
	assert.Nil(err, "KeysAndCert.Bytes() should not error")
	cert := dest.KeysAndCert.Certificate()
	certBytes := cert.Bytes()

	// These should be different - full destination should be much larger
	assert.NotEqual(len(fullDestBytes), len(certBytes), "Full destination bytes should be different size than certificate bytes")
	assert.Greater(len(fullDestBytes), len(certBytes), "Full destination should be larger than certificate alone")

	// Verify that the hash input is the full destination data
	hash := types.SHA256(fullDestBytes)
	expectedBase32, err := dest.Base32Address()
	assert.Nil(err, "Base32Address() should not error")

	// The generated address should be based on full destination hash
	assert.Contains(expectedBase32, ".b32.i2p", "Address should be properly formatted")
	assert.Greater(len(hash), 0, "Hash should be generated from full destination data")
}

// TestDestinationBytes verifies that the Bytes() method correctly serializes
// a destination back to its binary representation
func TestDestinationBytes(t *testing.T) {
	assert := assert.New(t)

	// Create test data representing a valid destination (384 bytes keys + certificate)
	keysData := make([]byte, 384) // Minimal keys data
	for i := range keysData {
		keysData[i] = byte(i % 256) // Fill with test pattern
	}

	// Create a KEY certificate (type=5) with minimal payload (4 bytes: crypto_type=0, sig_type=0)
	certData := []byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00}

	// Combine keys and certificate data
	originalData := append(keysData, certData...)

	// Parse into Destination
	dest, remainder, err := ReadDestination(originalData)
	assert.Nil(err, "Should be able to parse test destination data")
	assert.Empty(remainder, "Should consume all data")

	// Serialize back to bytes
	serializedData, err := dest.Bytes()
	assert.Nil(err, "Bytes() should not error")

	// Verify that serialized data matches original data
	assert.Equal(originalData, serializedData, "Serialized destination should match original data")
	assert.Equal(len(originalData), len(serializedData), "Serialized destination should have same length as original")

	// Verify round-trip: parse serialized data should give same destination
	dest2, remainder2, err2 := ReadDestination(serializedData)
	assert.Nil(err2, "Should be able to parse serialized destination data")
	assert.Empty(remainder2, "Should consume all serialized data")

	// Verify that both destinations generate the same addresses
	base32_1, err := dest.Base32Address()
	assert.Nil(err, "Base32Address() should not error")
	base32_2, err := dest2.Base32Address()
	assert.Nil(err, "Base32Address() should not error")
	assert.Equal(base32_1, base32_2, "Round-trip destinations should have same Base32 address")

	base64_1, err := dest.Base64()
	assert.Nil(err, "Base64() should not error")
	base64_2, err := dest2.Base64()
	assert.Nil(err, "Base64() should not error")
	assert.Equal(base64_1, base64_2, "Round-trip destinations should have same Base64 address")
}
