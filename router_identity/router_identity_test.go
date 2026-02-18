package router_identity

import (
	"crypto/rand"
	"testing"

	"github.com/go-i2p/common/keys_and_cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//
// Constructor Tests
//

// TestNewRouterIdentityFromKeysAndCert tests the simplified constructor
func TestNewRouterIdentityFromKeysAndCert(t *testing.T) {
	t.Run("valid KeysAndCert creates router identity", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)

		ri, err := NewRouterIdentityFromKeysAndCert(keysAndCert)
		require.NoError(t, err)
		require.NotNil(t, ri)
		assert.Equal(t, keysAndCert, ri.KeysAndCert)
		assert.True(t, ri.IsValid())
	})

	t.Run("nil KeysAndCert returns error", func(t *testing.T) {
		ri, err := NewRouterIdentityFromKeysAndCert(nil)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("invalid KeysAndCert returns error", func(t *testing.T) {
		// Create invalid KeysAndCert (nil key certificate)
		invalidKeysAndCert := &keys_and_cert.KeysAndCert{}

		ri, err := NewRouterIdentityFromKeysAndCert(invalidKeysAndCert)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "invalid KeysAndCert")
	})
}

// TestNewRouterIdentityFromBytes tests parsing router identities from byte slices
func TestNewRouterIdentityFromBytes(t *testing.T) {
	t.Run("valid bytes create router identity", func(t *testing.T) {
		originalData := createValidRouterIdentityBytes(t)

		ri, remainder, err := NewRouterIdentityFromBytes(originalData)
		require.NoError(t, err)
		require.NotNil(t, ri)
		assert.Empty(t, remainder)
		assert.True(t, ri.IsValid())
	})

	t.Run("invalid bytes return error", func(t *testing.T) {
		invalidData := []byte{0x00, 0x01, 0x02} // Too short

		ri, _, err := NewRouterIdentityFromBytes(invalidData)
		require.Error(t, err)
		assert.Nil(t, ri)
	})

	t.Run("empty bytes return error", func(t *testing.T) {
		ri, _, err := NewRouterIdentityFromBytes([]byte{})
		require.Error(t, err)
		assert.Nil(t, ri)
	})

	t.Run("extra bytes returned as remainder", func(t *testing.T) {
		originalData := createValidRouterIdentityBytes(t)
		extraBytes := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		dataWithExtra := append(originalData, extraBytes...)

		ri, remainder, err := NewRouterIdentityFromBytes(dataWithExtra)
		require.NoError(t, err)
		require.NotNil(t, ri)
		assert.Equal(t, extraBytes, remainder)
	})
}

//
// Validation Tests
//

// TestRouterIdentityValidate tests the Validate method
func TestRouterIdentityValidate(t *testing.T) {
	t.Run("valid router identity passes validation", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(keysAndCert)
		require.NoError(t, err)

		err = ri.Validate()
		assert.NoError(t, err)
	})

	t.Run("nil router identity fails validation", func(t *testing.T) {
		var ri *RouterIdentity
		err := ri.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "router identity is nil")
	})

	t.Run("router identity with nil KeysAndCert fails validation", func(t *testing.T) {
		ri := &RouterIdentity{KeysAndCert: nil}
		err := ri.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KeysAndCert is nil")
	})

	t.Run("router identity with invalid KeysAndCert fails validation", func(t *testing.T) {
		invalidKeysAndCert := &keys_and_cert.KeysAndCert{}
		ri := &RouterIdentity{KeysAndCert: invalidKeysAndCert}

		err := ri.Validate()
		require.Error(t, err)
	})
}

// TestRouterIdentityIsValid tests the IsValid convenience method
func TestRouterIdentityIsValid(t *testing.T) {
	t.Run("valid router identity returns true", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(keysAndCert)
		require.NoError(t, err)

		assert.True(t, ri.IsValid())
	})

	t.Run("nil router identity returns false", func(t *testing.T) {
		var ri *RouterIdentity
		assert.False(t, ri.IsValid())
	})

	t.Run("router identity with nil KeysAndCert returns false", func(t *testing.T) {
		ri := &RouterIdentity{KeysAndCert: nil}
		assert.False(t, ri.IsValid())
	})

	t.Run("router identity with invalid KeysAndCert returns false", func(t *testing.T) {
		invalidKeysAndCert := &keys_and_cert.KeysAndCert{}
		ri := &RouterIdentity{KeysAndCert: invalidKeysAndCert}

		assert.False(t, ri.IsValid())
	})
}

//
// Integration Tests
//

// TestRouterIdentityRoundTrip verifies constructor and serialization work together
func TestRouterIdentityRoundTrip(t *testing.T) {
	t.Run("NewRouterIdentityFromKeysAndCert -> ReadRouterIdentity", func(t *testing.T) {
		// Create original router identity
		keysAndCert := createValidKeysAndCert(t)
		ri1, err := NewRouterIdentityFromKeysAndCert(keysAndCert)
		require.NoError(t, err)

		// Serialize to bytes (via KeysAndCert)
		bytes1, err := ri1.KeysAndCert.Bytes()
		require.NoError(t, err)

		// Parse back from bytes
		ri2, remainder, err := NewRouterIdentityFromBytes(bytes1)
		require.NoError(t, err)
		assert.Empty(t, remainder)

		// Both should be valid
		assert.True(t, ri1.IsValid())
		assert.True(t, ri2.IsValid())

		// Assert byte-level round-trip equality
		bytes2, err := ri2.KeysAndCert.Bytes()
		require.NoError(t, err)
		assert.Equal(t, bytes1, bytes2, "round-trip bytes must be identical")
	})

	t.Run("validation after construction", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(keysAndCert)
		require.NoError(t, err)

		// RouterIdentity created with constructor should always be valid
		assert.NoError(t, ri.Validate())
		assert.True(t, ri.IsValid())
	})
}

// TestAsDestination verifies conversion to Destination
func TestAsDestination(t *testing.T) {
	t.Run("router identity converts to destination", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(keysAndCert)
		require.NoError(t, err)

		dest := ri.AsDestination()
		assert.NotNil(t, dest.KeysAndCert)
		assert.Equal(t, ri.KeysAndCert, dest.KeysAndCert)
	})
}

//
// Test Helpers
//

// createValidKeysAndCert creates a valid KeysAndCert for testing
func createValidKeysAndCert(t *testing.T) *keys_and_cert.KeysAndCert {
	t.Helper()

	// Create test router identity bytes and parse into KeysAndCert
	riBytes := createValidRouterIdentityBytes(t)
	keysAndCert, _, err := keys_and_cert.ReadKeysAndCert(riBytes)
	require.NoError(t, err, "Failed to create test KeysAndCert")

	return keysAndCert
}

// createValidRouterIdentityBytes creates valid router identity bytes for testing
func createValidRouterIdentityBytes(t *testing.T) []byte {
	t.Helper()

	// Create minimal valid keys data (384 bytes for default crypto)
	keysData := make([]byte, 384)
	_, err := rand.Read(keysData)
	require.NoError(t, err)

	// Create KEY certificate (type=5) with minimal valid payload
	// KeyCertificate structure:
	//   type (1 byte) = 5
	//   length (2 bytes) = 4
	//   sig_type (2 bytes) = 0 (DSA-SHA1) — signing type is first per spec
	//   crypto_type (2 bytes) = 0 (ElGamal) — crypto type is second per spec
	certData := []byte{
		0x05,       // type = KEY certificate (5)
		0x00, 0x04, // length = 4 bytes
		0x00, 0x00, // sig_type = 0 (DSA-SHA1)
		0x00, 0x00, // crypto_type = 0 (ElGamal)
	}

	// Combine keys and certificate
	return append(keysData, certData...)
}
