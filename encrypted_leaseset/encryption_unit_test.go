package encrypted_leaseset

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ————————————————————————————————————————————————
// Unit tests for EncryptInnerLeaseSet2 and DecryptInnerData
// Source: encryption.go (two-layer ChaCha20 + subcredential API)
// ————————————————————————————————————————————————

func TestEncryptDecryptRoundTrip(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	var subcredential [32]byte
	_, _ = rand.Read(subcredential[:])
	published := uint32(time.Now().Unix())

	encryptedData, err := EncryptInnerLeaseSet2(ls2, subcredential, published)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedData)
	// Minimum: outerSalt(32) + authType(1) + innerSalt(32) + plaintext(≥1)
	assert.GreaterOrEqual(t, len(encryptedData), ENCRYPTED_LEASESET_MIN_ENCRYPTED_SIZE)

	els := &EncryptedLeaseSet{
		encryptedInnerData: encryptedData,
		published:          published,
	}

	decryptedLS2, err := els.DecryptInnerData(subcredential)
	require.NoError(t, err)
	require.NotNil(t, decryptedLS2)

	assert.Equal(t, ls2.Published(), decryptedLS2.Published())
	assert.Equal(t, ls2.Expires(), decryptedLS2.Expires())
	assert.Equal(t, len(ls2.Leases()), len(decryptedLS2.Leases()))
}

func TestEncryptDecryptWithDifferentSubcredentials(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	var subcred1, subcred2 [32]byte
	_, _ = rand.Read(subcred1[:])
	_, _ = rand.Read(subcred2[:])
	published := uint32(time.Now().Unix())

	encryptedData, err := EncryptInnerLeaseSet2(ls2, subcred1, published)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{
		encryptedInnerData: encryptedData,
		published:          published,
	}

	// Decrypting with wrong subcredential should produce garbage (no AEAD tag to reject),
	// but the LeaseSet2 parser should fail on the resulting random bytes.
	_, err = els.DecryptInnerData(subcred2)
	assert.Error(t, err, "wrong subcredential should fail to parse as valid LeaseSet2")
}

func TestEncryptDecryptWithDifferentPublished(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	var subcredential [32]byte
	_, _ = rand.Read(subcredential[:])
	published := uint32(time.Now().Unix())

	encryptedData, err := EncryptInnerLeaseSet2(ls2, subcredential, published)
	require.NoError(t, err)

	// Use a different published timestamp for decryption
	els := &EncryptedLeaseSet{
		encryptedInnerData: encryptedData,
		published:          published + 1, // off by one
	}

	_, err = els.DecryptInnerData(subcredential)
	assert.Error(t, err, "wrong published timestamp should fail to parse")
}

func TestDecryptWithTooShortData(t *testing.T) {
	var subcredential [32]byte
	_, _ = rand.Read(subcredential[:])

	els := &EncryptedLeaseSet{
		encryptedInnerData: make([]byte, 10), // too short for outerSalt
		published:          uint32(time.Now().Unix()),
	}

	_, err := els.DecryptInnerData(subcredential)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	var subcredential [32]byte
	_, _ = rand.Read(subcredential[:])
	published := uint32(time.Now().Unix())

	ct1, err := EncryptInnerLeaseSet2(ls2, subcredential, published)
	require.NoError(t, err)
	ct2, err := EncryptInnerLeaseSet2(ls2, subcredential, published)
	require.NoError(t, err)

	// Random salts ensure different ciphertexts
	assert.NotEqual(t, ct1, ct2, "two encryptions of same data should differ due to random salts")
}

func TestDeriveSubcredentialDeterministic(t *testing.T) {
	destPub := make([]byte, 32)
	blindedPub := make([]byte, 32)
	_, _ = rand.Read(destPub)
	_, _ = rand.Read(blindedPub)

	sc1 := DeriveSubcredential(destPub, blindedPub)
	sc2 := DeriveSubcredential(destPub, blindedPub)
	assert.Equal(t, sc1, sc2, "subcredential derivation must be deterministic")
}

func TestDeriveSubcredentialDifferentInputsDifferentOutputs(t *testing.T) {
	dest1 := make([]byte, 32)
	dest2 := make([]byte, 32)
	blinded := make([]byte, 32)
	_, _ = rand.Read(dest1)
	_, _ = rand.Read(dest2)
	_, _ = rand.Read(blinded)

	sc1 := DeriveSubcredential(dest1, blinded)
	sc2 := DeriveSubcredential(dest2, blinded)
	assert.NotEqual(t, sc1, sc2, "different dest keys should produce different subcredentials")
}

func TestEncryptedDataStartsWithOuterSalt(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	var subcredential [32]byte
	_, _ = rand.Read(subcredential[:])
	published := uint32(time.Now().Unix())

	ct, err := EncryptInnerLeaseSet2(ls2, subcredential, published)
	require.NoError(t, err)

	// First 32 bytes are the outer salt (random, non-zero with high probability)
	outerSalt := ct[:ENCRYPTED_LEASESET_OUTER_SALT_SIZE]
	allZero := true
	for _, b := range outerSalt {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "outer salt should not be all zeros")
}

// TestEncryptionLayerStructure verifies that the outer salt is 32 bytes
// and manually decrypts Layer 1 to confirm the authType field.
func TestEncryptionLayerStructure(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)
	var subcredential [32]byte
	_, _ = rand.Read(subcredential[:])
	published := uint32(time.Now().Unix())

	ct, err := EncryptInnerLeaseSet2(ls2, subcredential, published)
	require.NoError(t, err)

	// First 32 bytes = outer salt
	assert.GreaterOrEqual(t, len(ct), 32)
	outerSalt := ct[:32]
	layer1CT := ct[32:]

	// Manually derive Layer 1 key and decrypt to verify structure
	ikm := buildLayerIKM(subcredential, published)
	key, iv, err := deriveLayerKey(outerSalt, ikm, "ELS2_L1K")
	require.NoError(t, err)

	layer1PT, err := chacha20Crypt(key, iv, layer1CT)
	require.NoError(t, err)

	// Layer 1 plaintext: authType(1) + innerSalt(32) + layer2CT
	require.GreaterOrEqual(t, len(layer1PT), 33)
	assert.Equal(t, byte(0), layer1PT[0], "authType must be 0 (no per-client auth)")
}

// TestDeriveSubcredentialMatchesSpec verifies the spec formula:
//
//	credential    = SHA-256("credential" || destSigningPubKey)
//	subcredential = SHA-256("subcredential" || credential || blindedPubKey)
func TestDeriveSubcredentialMatchesSpec(t *testing.T) {
	destPub := make([]byte, 32)
	blindedPub := make([]byte, 32)
	_, _ = rand.Read(destPub)
	_, _ = rand.Read(blindedPub)

	// Manual computation
	h1 := sha256.New()
	h1.Write([]byte("credential"))
	h1.Write(destPub)
	credential := h1.Sum(nil)

	h2 := sha256.New()
	h2.Write([]byte("subcredential"))
	h2.Write(credential)
	h2.Write(blindedPub)
	var expected [32]byte
	copy(expected[:], h2.Sum(nil))

	got := DeriveSubcredential(destPub, blindedPub)
	assert.Equal(t, expected, got, "subcredential must match spec formula")
}

// TestEncryptedDataLayerStructure manually decrypts both layers to verify the
// full encrypted data structure:
// outerSalt(32) || encrypted(authType(1) || innerSalt(32) || layer2CT)
func TestEncryptedDataLayerStructure(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	var subcredential [32]byte
	_, _ = rand.Read(subcredential[:])
	published := uint32(time.Now().Unix())

	ct, err := EncryptInnerLeaseSet2(ls2, subcredential, published)
	require.NoError(t, err)

	// Must start with 32-byte outer salt
	require.GreaterOrEqual(t, len(ct), ENCRYPTED_LEASESET_OUTER_SALT_SIZE)

	// After decrypting Layer 1, first byte must be authType
	outerSalt := ct[:ENCRYPTED_LEASESET_OUTER_SALT_SIZE]
	layer1CT := ct[ENCRYPTED_LEASESET_OUTER_SALT_SIZE:]
	ikm := buildLayerIKM(subcredential, published)

	key, iv, err := deriveLayerKey(outerSalt, ikm, "ELS2_L1K")
	require.NoError(t, err)

	layer1PT, err := chacha20Crypt(key, iv, layer1CT)
	require.NoError(t, err)

	assert.Equal(t, byte(ENCRYPTED_LEASESET_AUTH_TYPE_NONE), layer1PT[0],
		"first byte of Layer 1 plaintext must be authType=0")

	innerSalt := layer1PT[1 : 1+ENCRYPTED_LEASESET_INNER_SALT_SIZE]
	layer2CT := layer1PT[1+ENCRYPTED_LEASESET_INNER_SALT_SIZE:]

	// Decrypt Layer 2
	key2, iv2, err := deriveLayerKey(innerSalt, ikm, "ELS2_L2K")
	require.NoError(t, err)
	layer2PT, err := chacha20Crypt(key2, iv2, layer2CT)
	require.NoError(t, err)

	// Layer 2 plaintext must be a valid LeaseSet2
	assert.NotEmpty(t, layer2PT, "Layer 2 plaintext should contain LeaseSet2 data")
}
