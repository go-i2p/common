package encrypted_leaseset

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/x25519"
)

// createTestLeaseSet2 creates a minimal valid LeaseSet2 for testing
func createTestLeaseSet2(t *testing.T) *lease_set2.LeaseSet2 {
	t.Helper()

	// Create destination from raw bytes (like lease_set2 tests do)
	// This ensures the destination is properly sized (387+ bytes)
	destBytes := createTestDestinationBytes(t)
	dest, _, err := destination.ReadDestination(destBytes)
	require.NoError(t, err)

	// Generate X25519 key pair for LeaseSet2 encryption
	x25519Pub, _, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create encryption key for LeaseSet2 using X25519
	encryptionKey := lease_set2.EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: x25519Pub[:],
	}

	// Create a test lease2
	var tunnelGwHash data.Hash
	_, err = rand.Read(tunnelGwHash[:])
	require.NoError(t, err)

	tunnelID := uint32(12345)
	expiration := time.Now().Add(10 * time.Minute)

	testLease2, err := lease.NewLease2(tunnelGwHash, tunnelID, expiration)
	require.NoError(t, err)

	// Create LeaseSet2
	published := uint32(time.Now().Unix())
	expires := uint16(600) // 10 minutes
	flags := uint16(0)

	// Generate signing key
	_, ed25519SigningPriv, err := ed25519.GenerateEd25519KeyPair()
	require.NoError(t, err)

	ls2, err := lease_set2.NewLeaseSet2(
		dest,
		published,
		expires,
		flags,
		nil,            // no offline signature
		data.Mapping{}, // empty options
		[]lease_set2.EncryptionKey{encryptionKey},
		[]lease.Lease2{*testLease2},
		ed25519SigningPriv,
	)
	require.NoError(t, err)

	return &ls2
}

// createTestDestinationBytes creates minimal destination bytes for testing
// Returns 387+ byte destination (ElGamal + Ed25519)
func createTestDestinationBytes(t *testing.T) []byte {
	t.Helper()

	// Create 384 bytes of keys data (ElGamal 256 + Ed25519 32 + padding 96)
	keysData := make([]byte, 384)
	_, _ = rand.Read(keysData)

	// Create KEY certificate for Ed25519 signature
	certData := []byte{
		0x05,       // Certificate type = KEY (5)
		0x00, 0x04, // Certificate length = 4 bytes
		0x00, 0x07, // Signing key type = Ed25519 (7) big-endian
		0x00, 0x00, // Crypto key type = ElGamal (0) big-endian
	}

	// Combine: 384 (keys) + 7 (cert) = 391 bytes total
	return append(keysData, certData...)
}

// TestEncryptDecryptRoundTrip tests full encryption and decryption cycle
func TestEncryptDecryptRoundTrip(t *testing.T) {
	// Create test LeaseSet2
	ls2 := createTestLeaseSet2(t)

	// Generate recipient key pair
	recipientPub, recipientPriv, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Generate random cookie
	var cookie [32]byte
	_, err = rand.Read(cookie[:])
	require.NoError(t, err)

	// Encrypt
	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedData)
	assert.Greater(t, len(encryptedData), x25519.PublicKeySize+12+16, "Encrypted data should contain ephemeral key + nonce + ciphertext + tag")

	// Create EncryptedLeaseSet for decryption
	els := &EncryptedLeaseSet{
		cookie:             cookie,
		encryptedInnerData: encryptedData,
	}

	// Decrypt
	decryptedLS2, err := els.DecryptInnerData(cookie[:], &recipientPriv)
	require.NoError(t, err)
	require.NotNil(t, decryptedLS2)

	// Verify decrypted LeaseSet2 matches original (compare key fields not bytes since signature may differ)
	assert.Equal(t, ls2.Published(), decryptedLS2.Published(), "Published timestamp should match")
	assert.Equal(t, ls2.Expires(), decryptedLS2.Expires(), "Expiration should match")
	assert.Equal(t, ls2.Flags(), decryptedLS2.Flags(), "Flags should match")
	assert.Equal(t, len(ls2.EncryptionKeys()), len(decryptedLS2.EncryptionKeys()), "Should have same number of encryption keys")
	assert.Equal(t, len(ls2.Leases()), len(decryptedLS2.Leases()), "Should have same number of leases")
	assert.Equal(t, ls2.Published(), decryptedLS2.Published())
	assert.Equal(t, ls2.Expires(), decryptedLS2.Expires())
	assert.Equal(t, len(ls2.Leases()), len(decryptedLS2.Leases()))
}

// TestEncryptDecryptWithDifferentKeys tests that decryption fails with wrong key
func TestEncryptDecryptWithDifferentKeys(t *testing.T) {
	ls2 := createTestLeaseSet2(t)

	// Generate two different key pairs
	recipientPub1, _, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, recipientPriv2, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie [32]byte
	_, err = rand.Read(cookie[:])
	require.NoError(t, err)

	// Encrypt with first public key
	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub1)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{
		cookie:             cookie,
		encryptedInnerData: encryptedData,
	}

	// Attempt decryption with second private key (should fail)
	decryptedLS2, err := els.DecryptInnerData(cookie[:], recipientPriv2)
	assert.Error(t, err, "Decryption should fail with mismatched keys")
	assert.Nil(t, decryptedLS2)
	assert.Contains(t, err.Error(), "decryption failed", "Error should indicate decryption failure")
}

// TestDecryptWithWrongCookie tests cookie verification
func TestDecryptWithWrongCookie(t *testing.T) {
	ls2 := createTestLeaseSet2(t)

	recipientPub, recipientPriv, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie1 [32]byte
	var cookie2 [32]byte
	_, err = rand.Read(cookie1[:])
	require.NoError(t, err)
	_, err = rand.Read(cookie2[:])
	require.NoError(t, err)

	// Encrypt with cookie1
	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie1, recipientPub)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{
		cookie:             cookie1,
		encryptedInnerData: encryptedData,
	}

	// Try to decrypt with cookie2 (should fail cookie check)
	decryptedLS2, err := els.DecryptInnerData(cookie2[:], recipientPriv)
	assert.Error(t, err, "Decryption should fail with wrong cookie")
	assert.Nil(t, decryptedLS2)
	assert.Contains(t, err.Error(), "cookie mismatch", "Error should indicate cookie mismatch")
}

// TestDecryptWithInvalidCookieLength tests cookie length validation
func TestDecryptWithInvalidCookieLength(t *testing.T) {
	els := &EncryptedLeaseSet{
		cookie:             [32]byte{},
		encryptedInnerData: make([]byte, 100),
	}

	recipientPub, recipientPriv, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_ = recipientPub // Unused but needed for key generation

	// Test with short cookie
	shortCookie := make([]byte, 16)
	decryptedLS2, err := els.DecryptInnerData(shortCookie, recipientPriv)
	assert.Error(t, err)
	assert.Nil(t, decryptedLS2)
	assert.Contains(t, err.Error(), "invalid cookie length")

	// Test with long cookie
	longCookie := make([]byte, 64)
	decryptedLS2, err = els.DecryptInnerData(longCookie, recipientPriv)
	assert.Error(t, err)
	assert.Nil(t, decryptedLS2)
	assert.Contains(t, err.Error(), "invalid cookie length")
}

// TestDecryptWithTooShortEncryptedData tests encrypted data length validation
func TestDecryptWithTooShortEncryptedData(t *testing.T) {
	var cookie [32]byte
	_, err := rand.Read(cookie[:])
	require.NoError(t, err)

	els := &EncryptedLeaseSet{
		cookie:             cookie,
		encryptedInnerData: make([]byte, 40), // Too short (need at least 32+12+16 = 60)
	}

	_, recipientPriv, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	decryptedLS2, err := els.DecryptInnerData(cookie[:], &recipientPriv)
	assert.Error(t, err)
	assert.Nil(t, decryptedLS2)
	assert.Contains(t, err.Error(), "encrypted data too short")
}

// TestDecryptWithInvalidPrivateKeyType tests private key type validation
func TestDecryptWithInvalidPrivateKeyType(t *testing.T) {
	var cookie [32]byte
	els := &EncryptedLeaseSet{
		cookie:             cookie,
		encryptedInnerData: make([]byte, 100),
	}

	// Test with invalid type (string)
	decryptedLS2, err := els.DecryptInnerData(cookie[:], "not a key")
	assert.Error(t, err)
	assert.Nil(t, decryptedLS2)
	assert.Contains(t, err.Error(), "invalid private key type")

	// Test with wrong length []byte
	shortKey := make([]byte, 16)
	decryptedLS2, err = els.DecryptInnerData(cookie[:], shortKey)
	assert.Error(t, err)
	assert.Nil(t, decryptedLS2)
}

// TestDecryptWithByteSlicePrivateKey tests []byte private key support
func TestDecryptWithByteSlicePrivateKey(t *testing.T) {
	ls2 := createTestLeaseSet2(t)

	recipientPub, recipientPriv, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie [32]byte
	_, err = rand.Read(cookie[:])
	require.NoError(t, err)

	// Encrypt
	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{
		cookie:             cookie,
		encryptedInnerData: encryptedData,
	}

	// Decrypt using []byte private key
	privKeyBytes := recipientPriv[:]
	decryptedLS2, err := els.DecryptInnerData(cookie[:], privKeyBytes)
	require.NoError(t, err)
	require.NotNil(t, decryptedLS2)

	// Verify decrypted LeaseSet2 matches original (compare key fields not bytes since signature may differ)
	assert.Equal(t, ls2.Published(), decryptedLS2.Published(), "Published timestamp should match")
	assert.Equal(t, ls2.Expires(), decryptedLS2.Expires(), "Expiration should match")
	assert.Equal(t, len(ls2.EncryptionKeys()), len(decryptedLS2.EncryptionKeys()), "Should have same number of encryption keys")
	assert.Equal(t, len(ls2.Leases()), len(decryptedLS2.Leases()), "Should have same number of leases")
}

// TestEncryptWithCurve25519PublicKey tests Curve25519PublicKey support
func TestEncryptWithCurve25519PublicKey(t *testing.T) {
	ls2 := createTestLeaseSet2(t)

	recipientPub, recipientPriv, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie [32]byte
	_, err = rand.Read(cookie[:])
	require.NoError(t, err)

	// Use Curve25519PublicKey type
	c25519Pub := curve25519.Curve25519PublicKey(recipientPub[:])

	// Encrypt
	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, c25519Pub)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{
		cookie:             cookie,
		encryptedInnerData: encryptedData,
	}

	// Decrypt should work
	decryptedLS2, err := els.DecryptInnerData(cookie[:], &recipientPriv)
	require.NoError(t, err)
	require.NotNil(t, decryptedLS2)
}

// TestEncryptWithByteSlicePublicKey tests []byte public key support
func TestEncryptWithByteSlicePublicKey(t *testing.T) {
	ls2 := createTestLeaseSet2(t)

	recipientPub, recipientPriv, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie [32]byte
	_, err = rand.Read(cookie[:])
	require.NoError(t, err)

	// Use []byte public key
	pubKeyBytes := recipientPub[:]

	// Encrypt
	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, pubKeyBytes)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{
		cookie:             cookie,
		encryptedInnerData: encryptedData,
	}

	// Decrypt should work
	decryptedLS2, err := els.DecryptInnerData(cookie[:], &recipientPriv)
	require.NoError(t, err)
	require.NotNil(t, decryptedLS2)
}

// TestEncryptWithInvalidPublicKeyType tests public key type validation
func TestEncryptWithInvalidPublicKeyType(t *testing.T) {
	ls2 := createTestLeaseSet2(t)

	var cookie [32]byte
	_, err := rand.Read(cookie[:])
	require.NoError(t, err)

	// Test with invalid type
	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, "not a key")
	assert.Error(t, err)
	assert.Nil(t, encryptedData)
	assert.Contains(t, err.Error(), "invalid public key type")

	// Test with wrong length []byte
	shortKey := make([]byte, 16)
	encryptedData, err = EncryptInnerLeaseSet2(ls2, cookie, shortKey)
	assert.Error(t, err)
	assert.Nil(t, encryptedData)
	assert.Contains(t, err.Error(), "invalid public key length")
}

// TestEncryptionDeterminism tests that encryption produces different outputs each time
func TestEncryptionNonDeterminism(t *testing.T) {
	ls2 := createTestLeaseSet2(t)

	recipientPub, _, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie [32]byte
	_, err = rand.Read(cookie[:])
	require.NoError(t, err)

	// Encrypt twice with same inputs
	encrypted1, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub)
	require.NoError(t, err)

	encrypted2, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub)
	require.NoError(t, err)

	// Should produce different ciphertexts (due to fresh ephemeral keys and nonces)
	assert.NotEqual(t, encrypted1, encrypted2, "Encryption should produce different outputs due to randomness")
}

// TestEncryptionForwardSecrecy tests that different ephemeral keys are used
func TestEncryptionForwardSecrecy(t *testing.T) {
	ls2 := createTestLeaseSet2(t)

	recipientPub, recipientPriv, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie [32]byte
	_, err = rand.Read(cookie[:])
	require.NoError(t, err)

	// Encrypt multiple times
	encrypted1, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub)
	require.NoError(t, err)

	encrypted2, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub)
	require.NoError(t, err)

	// Extract ephemeral public keys (first 32 bytes)
	ephemeral1 := encrypted1[:32]
	ephemeral2 := encrypted2[:32]

	// Ephemeral keys should be different (forward secrecy)
	assert.NotEqual(t, ephemeral1, ephemeral2, "Each encryption should use a fresh ephemeral key pair")

	// Both should still decrypt correctly
	els1 := &EncryptedLeaseSet{cookie: cookie, encryptedInnerData: encrypted1}
	els2 := &EncryptedLeaseSet{cookie: cookie, encryptedInnerData: encrypted2}

	decrypted1, err := els1.DecryptInnerData(cookie[:], &recipientPriv)
	require.NoError(t, err)

	decrypted2, err := els2.DecryptInnerData(cookie[:], &recipientPriv)
	require.NoError(t, err)

	// Both should produce the same LeaseSet2
	decr1Addr, err := decrypted1.Destination().Base32Address()
	require.NoError(t, err)
	decr2Addr, err := decrypted2.Destination().Base32Address()
	require.NoError(t, err)
	assert.Equal(t, decr1Addr, decr2Addr)
}

// TestEncryptionWithMultipleCookies tests that different cookies produce different encryptions
func TestEncryptionWithMultipleCookies(t *testing.T) {
	ls2 := createTestLeaseSet2(t)

	recipientPub, recipientPriv, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie1, cookie2 [32]byte
	_, err = rand.Read(cookie1[:])
	require.NoError(t, err)
	_, err = rand.Read(cookie2[:])
	require.NoError(t, err)

	// Encrypt with different cookies
	encrypted1, err := EncryptInnerLeaseSet2(ls2, cookie1, recipientPub)
	require.NoError(t, err)

	encrypted2, err := EncryptInnerLeaseSet2(ls2, cookie2, recipientPub)
	require.NoError(t, err)

	// Encrypted data should differ
	assert.NotEqual(t, encrypted1, encrypted2)

	// Each should decrypt with its respective cookie
	els1 := &EncryptedLeaseSet{cookie: cookie1, encryptedInnerData: encrypted1}
	els2 := &EncryptedLeaseSet{cookie: cookie2, encryptedInnerData: encrypted2}

	decrypted1, err := els1.DecryptInnerData(cookie1[:], recipientPriv)
	require.NoError(t, err)

	decrypted2, err := els2.DecryptInnerData(cookie2[:], recipientPriv)
	require.NoError(t, err)

	// Both should produce the same LeaseSet2
	assert.Equal(t, decrypted1.Published(), decrypted2.Published())
}

// BenchmarkEncryptInnerLeaseSet2 benchmarks encryption performance
func BenchmarkEncryptInnerLeaseSet2(b *testing.B) {
	ls2 := createTestLeaseSet2(&testing.T{})

	recipientPub, _, err := x25519.GenerateKey(rand.Reader)
	require.NoError(b, err)

	var cookie [32]byte
	_, err = rand.Read(cookie[:])
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecryptInnerData benchmarks decryption performance
func BenchmarkDecryptInnerData(b *testing.B) {
	ls2 := createTestLeaseSet2(&testing.T{})

	recipientPub, recipientPriv, err := x25519.GenerateKey(rand.Reader)
	require.NoError(b, err)

	var cookie [32]byte
	_, err = rand.Read(cookie[:])
	require.NoError(b, err)

	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub)
	require.NoError(b, err)

	els := &EncryptedLeaseSet{
		cookie:             cookie,
		encryptedInnerData: encryptedData,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := els.DecryptInnerData(cookie[:], &recipientPriv)
		if err != nil {
			b.Fatal(err)
		}
	}
}
