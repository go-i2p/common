package encrypted_leaseset

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/kdf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ————————————————————————————————————————————————
// Unit tests for CreateBlindedDestination and VerifyBlindedSignature
// Source: blinding.go
// ————————————————————————————————————————————————

func TestCreateBlindedDestination(t *testing.T) {
	dest := createTestEd25519Destination(t)

	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	date := time.Now()
	blindedDest, err := CreateBlindedDestination(dest, secret, date)
	require.NoError(t, err, "CreateBlindedDestination should succeed")

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

func TestCreateBlindedDestinationDifferentDates(t *testing.T) {
	dest := createTestEd25519Destination(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	date1 := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)
	date2 := time.Date(2025, 11, 25, 0, 0, 0, 0, time.UTC)

	blindedDest1, err := CreateBlindedDestination(dest, secret, date1)
	require.NoError(t, err, "CreateBlindedDestination for date1 should succeed")

	blindedDest2, err := CreateBlindedDestination(dest, secret, date2)
	require.NoError(t, err, "CreateBlindedDestination for date2 should succeed")

	key1, err := blindedDest1.SigningPublicKey()
	require.NoError(t, err)
	key2, err := blindedDest2.SigningPublicKey()
	require.NoError(t, err)
	assert.NotEqual(t, key1.Bytes(), key2.Bytes(),
		"Different dates should produce different blinded keys")
}

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

func TestCreateBlindedDestinationUnsupportedSignatureType(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	date := time.Now()

	keyCert, err := key_certificate.NewKeyCertificateWithTypes(
		0,                                  // DSA SHA1 (type 0, not supported for blinding)
		key_certificate.KEYCERT_CRYPTO_ELG, // ElGamal encryption
	)
	require.NoError(t, err)

	padding := make([]byte, 0)

	keysAndCert, err := keys_and_cert.NewKeysAndCert(
		keyCert,
		nil,
		padding,
		nil,
	)

	dest := destination.Destination{KeysAndCert: keysAndCert}

	_, err = CreateBlindedDestination(dest, secret, date)
	assert.Error(t, err, "Should fail with unsupported signature type")
}

func TestVerifyBlindedSignature(t *testing.T) {
	dest := createTestEd25519Destination(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	date := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)

	blindedDest, err := CreateBlindedDestination(dest, secret, date)
	require.NoError(t, err, "CreateBlindedDestination should succeed")

	alpha, err := kdf.DeriveBlindingFactor(secret, "2025-11-24")
	require.NoError(t, err, "DeriveBlindingFactor should succeed")

	valid := VerifyBlindedSignature(blindedDest, dest, alpha)
	assert.True(t, valid, "Blinded signature should verify successfully")
}

func TestVerifyBlindedSignatureWrongAlpha(t *testing.T) {
	dest := createTestEd25519Destination(t)
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	date := time.Now()

	blindedDest, err := CreateBlindedDestination(dest, secret, date)
	require.NoError(t, err, "CreateBlindedDestination should succeed")

	var wrongAlpha [32]byte
	_, _ = rand.Read(wrongAlpha[:])

	valid := VerifyBlindedSignature(blindedDest, dest, wrongAlpha)
	assert.False(t, valid, "Verification should fail with wrong alpha")
}

func TestVerifyBlindedSignatureWrongOriginal(t *testing.T) {
	dest1 := createTestEd25519Destination(t)
	dest2 := createTestEd25519Destination(t) // Different destination
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	date := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)

	blindedDest, err := CreateBlindedDestination(dest1, secret, date)
	require.NoError(t, err, "CreateBlindedDestination should succeed")

	alpha, err := kdf.DeriveBlindingFactor(secret, "2025-11-24")
	require.NoError(t, err, "DeriveBlindingFactor should succeed")

	valid := VerifyBlindedSignature(blindedDest, dest2, alpha)
	assert.False(t, valid, "Verification should fail with wrong original destination")
}

func TestBlindingDeterminism(t *testing.T) {
	original := createTestEd25519Destination(t)
	secret := make([]byte, 32)
	copy(secret, []byte("this is a test secret for determinism"))
	date := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)

	blindings := make([]destination.Destination, 5)
	for i := 0; i < 5; i++ {
		blinded, err := CreateBlindedDestination(original, secret, date)
		require.NoError(t, err, "Blinding iteration %d should succeed", i)
		blindings[i] = blinded
	}

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
