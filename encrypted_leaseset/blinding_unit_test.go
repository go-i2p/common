package encrypted_leaseset

import (
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	goi2ped25519 "github.com/go-i2p/crypto/ed25519"
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
	// Per https://geti2p.net/spec/encryptedleaseset, the blinded public key
	// signature type "will always be type 11, identifying a Red25519 blinded
	// key", regardless of the original destination's signing type.
	assert.Equal(t, key_certificate.KEYCERT_SIGN_REDDSA_ED25519, blindedDest.KeyCertificate.SigningPublicKeyType(),
		"Blinded destination must declare RedDSA (11) as its signing key type")
	assert.Equal(t, dest.KeyCertificate.PublicKeyType(), blindedDest.KeyCertificate.PublicKeyType(),
		"Blinded destination should preserve the crypto key type")

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

// TestCreateBlindedDestinationSecretLengths verifies that the blinding secret is
// treated as the optional variable-length UTF-8 string the spec describes
// ("secret is optional, else zero-length") rather than a fixed 32-byte key.
// Short and empty secrets must all succeed, and each must produce a distinct
// blinded key.
func TestCreateBlindedDestinationSecretLengths(t *testing.T) {
	dest := createTestEd25519Destination(t)
	date := time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC)

	secrets := [][]byte{
		nil,
		{},
		[]byte("hunter2"),
		make([]byte, 16),
		make([]byte, 24),
		make([]byte, 32),
	}

	seen := make(map[string]int)
	for i, secret := range secrets {
		blinded, err := CreateBlindedDestination(dest, secret, date)
		require.NoError(t, err, "secret length %d must be accepted (secret is optional per spec)", len(secret))

		spk, err := blinded.SigningPublicKey()
		require.NoError(t, err)
		key := string(spk.Bytes())
		if prev, dup := seen[key]; dup {
			t.Errorf("secret %d duplicates secret %d; distinct secrets must yield distinct blinded keys", i, prev)
		}
		seen[key] = i
	}
}

// TestBlindingAlphaBoundToDestination verifies the security property the spec's
// GENERATE_ALPHA() provides: alpha (and therefore the blinded key) is bound to
// the destination's signing public key, so one secret cannot produce the same
// blinding factor across different destinations.
func TestBlindingAlphaBoundToDestination(t *testing.T) {
	dest1 := createTestEd25519Destination(t)
	dest2 := createTestEd25519Destination(t)
	secret := []byte("shared-secret")
	date := time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC)

	alpha1 := deriveTestAlpha(t, dest1, secret, date)
	alpha2 := deriveTestAlpha(t, dest2, secret, date)

	assert.NotEqual(t, alpha1, alpha2,
		"alpha must depend on the destination signing key, not only on secret+date")
}

// TestBlindingUsesSpecAlphaDerivation verifies that CreateBlindedDestination
// produces exactly the blinded key A' = A + [alpha]B for the spec's alpha, where
// alpha is bound to the destination signing key and signature type
// (https://geti2p.net/spec/encryptedleaseset §"Blinding Calculations").
//
// The test derives alpha independently of the package's internal helper and
// applies the point blinding directly, so a regression back to the previous
// secret-only (destination-independent) construction would fail.
func TestBlindingUsesSpecAlphaDerivation(t *testing.T) {
	dest := createTestEd25519Destination(t)
	secret := []byte("spec-vector-secret")
	date := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)

	spk, err := dest.SigningPublicKey()
	require.NoError(t, err)
	var a [32]byte
	copy(a[:], spk.Bytes())

	// alpha per spec: salt binds A || stA || stA'(=11), ikm = yyyyMMdd || secret.
	alpha, err := kdf.DeriveBlindingFactorI2P(
		a[:], string(secret), uint16(key_certificate.KEYCERT_SIGN_ED25519), date,
	)
	require.NoError(t, err)

	expected, err := goi2ped25519.BlindPublicKey(a, alpha)
	require.NoError(t, err)

	blinded, err := CreateBlindedDestination(dest, secret, date)
	require.NoError(t, err)

	blindedSpk, err := blinded.SigningPublicKey()
	require.NoError(t, err)
	assert.Equal(t, expected[:], blindedSpk.Bytes(),
		"blinded key must equal A + [alpha]B for the spec-derived alpha")

	assert.True(t, VerifyBlindedSignature(blinded, dest, alpha),
		"blinded destination must verify against the spec-derived alpha")
}

// TestCreateBlindedDestinationUnsupportedSignatureType verifies that
// CreateBlindedDestination rejects a destination whose signature type is not
// Ed25519 or RedDSA. Blinding only supports those two signature types, so a
// destination using the legacy DSA signature type must be refused.
func TestCreateBlindedDestinationUnsupportedSignatureType(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	date := time.Now()

	// Build a 391-byte destination whose key certificate declares the legacy
	// DSA signature type (0) with ElGamal encryption.
	destBytes := make([]byte, 391)
	_, _ = rand.Read(destBytes[:384])

	// Certificate: type=KEY(5), length=4, sigtype=DSA(0), cryptotype=ElGamal(0)
	destBytes[384] = 0x05
	destBytes[385] = 0x00
	destBytes[386] = 0x04
	destBytes[387] = 0x00
	destBytes[388] = 0x00
	destBytes[389] = 0x00
	destBytes[390] = 0x00

	dest, _, err := destination.ReadDestination(destBytes)
	require.NoError(t, err, "Failed to read destination")

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

	alpha := deriveTestAlpha(t, dest, secret, date)

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

	// alpha derived for dest1 must not verify dest2: blinding is destination-bound
	alpha := deriveTestAlpha(t, dest1, secret, date)

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
