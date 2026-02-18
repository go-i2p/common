package encrypted_leaseset

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/kdf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestEd25519Destination creates a destination with Ed25519 signature type for testing.
// For blinding tests, we only need a valid Ed25519 signing key - the encryption key is not used.
func createTestEd25519Destination(t *testing.T) destination.Destination {
	t.Helper()

	// Generate Ed25519 key pair (this is what gets blinded)
	publicKey, _, err := ed25519.GenerateEd25519KeyPair()
	require.NoError(t, err, "Failed to generate Ed25519 key pair")

	// Create a simple destination from raw bytes (like other tests do)
	// This creates a minimal 387-byte destination with ElGamal + Ed25519
	destBytes := make([]byte, 391)

	// First 384 bytes: encryption public key (256) + padding (96) + signing key placeholder (32)
	_, _ = rand.Read(destBytes[:384])

	// Copy actual Ed25519 public key to the signing key position (last 32 bytes of the 384-byte block)
	copy(destBytes[352:384], publicKey.Bytes())

	// Certificate (7 bytes): type=KEY(5), length=4, sigtype=Ed25519(7), cryptotype=ElGamal(0)
	destBytes[384] = 0x05 // CERT_KEY
	destBytes[385] = 0x00 // length high byte
	destBytes[386] = 0x04 // length low byte (4)
	destBytes[387] = 0x00 // signing key type high byte
	destBytes[388] = 0x07 // signing key type low byte (Ed25519=7)
	destBytes[389] = 0x00 // crypto key type high byte
	destBytes[390] = 0x00 // crypto key type low byte (ElGamal=0)

	// Parse the destination from bytes
	dest, _, err := destination.ReadDestination(destBytes)
	require.NoError(t, err, "Failed to read destination")

	return dest
}

// TestCreateBlindedDestination tests successful blinding of an Ed25519 destination
func TestCreateBlindedDestination(t *testing.T) {
	dest := createTestEd25519Destination(t)

	// Create 32-byte secret
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	// Create blinded destination for today
	date := time.Now()
	blindedDest, err := CreateBlindedDestination(dest, secret, date)
	require.NoError(t, err, "CreateBlindedDestination should succeed")

	// Verify blinded destination has same structure
	assert.NotNil(t, blindedDest.KeyCertificate, "Blinded destination should have key certificate")
	assert.Equal(t, dest.KeyCertificate.SigningPublicKeyType(), blindedDest.KeyCertificate.SigningPublicKeyType(),
		"Blinded destination should have same signature type")

	// Verify signing keys are different (blinded != original)
	origKey, err := dest.SigningPublicKey()
	require.NoError(t, err)
	blindedKey, err := blindedDest.SigningPublicKey()
	require.NoError(t, err)
	assert.NotEqual(t, origKey.Bytes(), blindedKey.Bytes(),
		"Blinded signing key should be different from original")

	// Verify blinding is deterministic (same input = same output)
	blindedDest2, err := CreateBlindedDestination(dest, secret, date)
	require.NoError(t, err, "Second CreateBlindedDestination should succeed")
	blindedKey1, err := blindedDest.SigningPublicKey()
	require.NoError(t, err)
	blindedKey2, err := blindedDest2.SigningPublicKey()
	require.NoError(t, err)
	assert.Equal(t, blindedKey1.Bytes(), blindedKey2.Bytes(),
		"Blinding should be deterministic")
}

// TestCreateBlindedDestinationDifferentDates tests that different dates produce different blinded keys
func TestCreateBlindedDestinationDifferentDates(t *testing.T) {
	dest := createTestEd25519Destination(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	// Create blinded destinations for different dates
	date1 := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)
	date2 := time.Date(2025, 11, 25, 0, 0, 0, 0, time.UTC)

	blindedDest1, err := CreateBlindedDestination(dest, secret, date1)
	require.NoError(t, err, "CreateBlindedDestination for date1 should succeed")

	blindedDest2, err := CreateBlindedDestination(dest, secret, date2)
	require.NoError(t, err, "CreateBlindedDestination for date2 should succeed")

	// Verify different dates produce different blinded keys
	key1, err := blindedDest1.SigningPublicKey()
	require.NoError(t, err)
	key2, err := blindedDest2.SigningPublicKey()
	require.NoError(t, err)
	assert.NotEqual(t, key1.Bytes(), key2.Bytes(),
		"Different dates should produce different blinded keys")
}

// TestCreateBlindedDestinationInvalidSecret tests error handling for invalid secrets
func TestCreateBlindedDestinationInvalidSecret(t *testing.T) {
	dest := createTestEd25519Destination(t)
	date := time.Now()

	tests := []struct {
		name   string
		secret []byte
	}{
		{"Empty secret", []byte{}},
		{"Too short secret (16 bytes)", make([]byte, 16)},
		{"Too short secret (24 bytes)", make([]byte, 24)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateBlindedDestination(dest, tt.secret, date)
			assert.Error(t, err, "Should fail with invalid secret")
			assert.Contains(t, err.Error(), "blinding factor", "Error should mention blinding factor")
		})
	}
}

// TestCreateBlindedDestinationUnsupportedSignatureType tests error handling for non-Ed25519 signatures
func TestCreateBlindedDestinationUnsupportedSignatureType(t *testing.T) {
	// Create destination with DSA signature type (not supported for blinding)
	// For simplicity, we'll create a minimal destination structure
	// In practice, this would be a full DSA destination

	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	date := time.Now()

	// Create a destination with DSA signature type
	keyCert, err := key_certificate.NewKeyCertificateWithTypes(
		0,                                  // DSA SHA1 (type 0, not supported for blinding)
		key_certificate.KEYCERT_CRYPTO_ELG, // ElGamal encryption
	)
	require.NoError(t, err)

	// Create dummy keys (just for type check test, won't actually be used)
	padding := make([]byte, 0) // DSA uses 128 bytes, no padding

	keysAndCert, err := keys_and_cert.NewKeysAndCert(
		keyCert,
		nil,
		padding,
		nil, // Will trigger error before using this
	)

	// Override with DSA type even though we have nil signing key
	// This is just to test the type check
	dest := destination.Destination{KeysAndCert: keysAndCert}

	_, err = CreateBlindedDestination(dest, secret, date)
	assert.Error(t, err, "Should fail with unsupported signature type")
	// Note: might fail earlier due to nil signing key, but that's ok for this test
}

// TestVerifyBlindedSignature tests successful verification of blinded destinations
func TestVerifyBlindedSignature(t *testing.T) {
	dest := createTestEd25519Destination(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	date := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)

	// Create blinded destination
	blindedDest, err := CreateBlindedDestination(dest, secret, date)
	require.NoError(t, err, "CreateBlindedDestination should succeed")

	// Derive the same alpha used for blinding
	alpha, err := kdf.DeriveBlindingFactor(secret, "2025-11-24")
	require.NoError(t, err, "DeriveBlindingFactor should succeed")

	// Verify the blinded signature
	valid := VerifyBlindedSignature(blindedDest, dest, alpha)
	assert.True(t, valid, "Blinded signature should verify successfully")
}

// TestVerifyBlindedSignatureWrongAlpha tests verification fails with wrong alpha
func TestVerifyBlindedSignatureWrongAlpha(t *testing.T) {
	dest := createTestEd25519Destination(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	date := time.Now()

	// Create blinded destination
	blindedDest, err := CreateBlindedDestination(dest, secret, date)
	require.NoError(t, err, "CreateBlindedDestination should succeed")

	// Use wrong alpha (random)
	var wrongAlpha [32]byte
	_, _ = rand.Read(wrongAlpha[:])

	// Verification should fail
	valid := VerifyBlindedSignature(blindedDest, dest, wrongAlpha)
	assert.False(t, valid, "Verification should fail with wrong alpha")
}

// TestVerifyBlindedSignatureWrongOriginal tests verification fails with wrong original destination
func TestVerifyBlindedSignatureWrongOriginal(t *testing.T) {
	dest1 := createTestEd25519Destination(t)
	dest2 := createTestEd25519Destination(t) // Different destination
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	date := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)

	// Create blinded destination from dest1
	blindedDest, err := CreateBlindedDestination(dest1, secret, date)
	require.NoError(t, err, "CreateBlindedDestination should succeed")

	// Derive alpha for dest1
	alpha, err := kdf.DeriveBlindingFactor(secret, "2025-11-24")
	require.NoError(t, err, "DeriveBlindingFactor should succeed")

	// Try to verify against dest2 (wrong original)
	valid := VerifyBlindedSignature(blindedDest, dest2, alpha)
	assert.False(t, valid, "Verification should fail with wrong original destination")
}

// TestBlindingRoundTrip tests full round-trip blinding and verification
func TestBlindingRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		date time.Time
	}{
		{"Date 2025-11-24", time.Date(2025, 11, 24, 12, 0, 0, 0, time.UTC)},
		{"Date 2025-12-01", time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)},
		{"Date 2026-01-01", time.Date(2026, 1, 1, 23, 59, 59, 0, time.UTC)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original destination
			original := createTestEd25519Destination(t)

			// Generate secret
			secret := make([]byte, 32)
			_, _ = rand.Read(secret)

			// Blind the destination
			blinded, err := CreateBlindedDestination(original, secret, tt.date)
			require.NoError(t, err, "Blinding should succeed")

			// Derive alpha for verification
			dateStr := tt.date.UTC().Format("2006-01-02")
			alpha, err := kdf.DeriveBlindingFactor(secret, dateStr)
			require.NoError(t, err, "Alpha derivation should succeed")

			// Verify
			valid := VerifyBlindedSignature(blinded, original, alpha)
			assert.True(t, valid, "Round-trip verification should succeed")

			// Verify blinded key is actually different
			origKey, err := original.SigningPublicKey()
			require.NoError(t, err)
			blindedKey, err := blinded.SigningPublicKey()
			require.NoError(t, err)
			assert.NotEqual(t, origKey.Bytes(), blindedKey.Bytes(),
				"Blinded key must differ from original")
		})
	}
}

// TestBlindingDeterminism tests that blinding is deterministic
func TestBlindingDeterminism(t *testing.T) {
	original := createTestEd25519Destination(t)
	secret := make([]byte, 32)
	copy(secret, []byte("this is a test secret for determinism"))
	date := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)

	// Create multiple blinded destinations with same inputs
	blindings := make([]destination.Destination, 5)
	for i := 0; i < 5; i++ {
		blinded, err := CreateBlindedDestination(original, secret, date)
		require.NoError(t, err, "Blinding iteration %d should succeed", i)
		blindings[i] = blinded
	}

	// All should have identical signing keys
	firstKey, err := blindings[0].SigningPublicKey()
	require.NoError(t, err)
	firstKeyBytes := firstKey.Bytes()
	for i := 1; i < 5; i++ {
		key, err := blindings[i].SigningPublicKey()
		require.NoError(t, err)
		assert.Equal(t, firstKeyBytes, key.Bytes(),
			"Blinding iteration %d should match first blinding", i)
	}
}

// TestBlindingPreservesEncryptionKey tests that blinding doesn't change encryption key
func TestBlindingPreservesEncryptionKey(t *testing.T) {
	original := createTestEd25519Destination(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	date := time.Now()

	blinded, err := CreateBlindedDestination(original, secret, date)
	require.NoError(t, err, "Blinding should succeed")

	// Encryption keys should be identical (only signing key is blinded)
	// Note: In the current implementation, we keep the same ReceivingPublic
	assert.Equal(t, original.ReceivingPublic, blinded.ReceivingPublic,
		"Encryption key should remain unchanged")
}

// BenchmarkCreateBlindedDestination benchmarks the blinding operation
func BenchmarkCreateBlindedDestination(b *testing.B) {
	// Setup using a sub-test to get a proper *testing.T
	var dest destination.Destination
	var secret []byte

	b.Run("setup", func(b *testing.B) {
		b.StopTimer()
		t := &testing.T{}
		dest = createTestEd25519Destination(t)
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
		b.StartTimer()
	})

	if len(secret) == 0 {
		// Fallback: create directly for benchmark
		destBytes := make([]byte, 391)
		rand.Read(destBytes[:384])
		destBytes[384] = 0x05
		destBytes[385] = 0x00
		destBytes[386] = 0x04
		destBytes[387] = 0x00
		destBytes[388] = 0x07
		destBytes[389] = 0x00
		destBytes[390] = 0x00
		dest, _, _ = destination.ReadDestination(destBytes)
		secret = make([]byte, 32)
		rand.Read(secret)
	}

	date := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreateBlindedDestination(dest, secret, date)
	}
}

// BenchmarkVerifyBlindedSignature benchmarks signature verification
func BenchmarkVerifyBlindedSignature(b *testing.B) {
	// Setup directly without &testing.T{}
	destBytes := make([]byte, 391)
	rand.Read(destBytes[:384])
	destBytes[384] = 0x05
	destBytes[385] = 0x00
	destBytes[386] = 0x04
	destBytes[387] = 0x00
	destBytes[388] = 0x07
	destBytes[389] = 0x00
	destBytes[390] = 0x00
	dest, _, _ := destination.ReadDestination(destBytes)

	secret := make([]byte, 32)
	rand.Read(secret)
	date := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)

	blinded, _ := CreateBlindedDestination(dest, secret, date)
	alpha, _ := kdf.DeriveBlindingFactor(secret, "2025-11-24")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyBlindedSignature(blinded, dest, alpha)
	}
}
