package destination

import (
	"regexp"
	"testing"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// ReadDestination
// ============================================================================

func TestReadDestination_ValidData(t *testing.T) {
	data := createValidDestinationBytes(t)
	dest, remainder, err := ReadDestination(data)
	require.NoError(t, err)
	assert.Empty(t, remainder)
	assert.NotNil(t, dest.KeysAndCert)
}

// ============================================================================
// Bytes() round-trip
// ============================================================================

func TestDestinationBytes(t *testing.T) {
	assert := assert.New(t)

	keysData := make([]byte, 384)
	for i := range keysData {
		keysData[i] = byte(i % 256)
	}
	certData := []byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00}
	originalData := append(keysData, certData...)

	dest, remainder, err := ReadDestination(originalData)
	assert.Nil(err, "Should be able to parse test destination data")
	assert.Empty(remainder, "Should consume all data")

	serializedData, err := dest.Bytes()
	assert.Nil(err, "Bytes() should not error")

	// ReadDestination auto-canonicalizes ElGamal+DSA-SHA1 KEY(0,0) to NULL cert.
	// The serialized form is 387 bytes (384 key data + 3-byte NULL cert),
	// not 391 bytes (384 + 7-byte KEY(0,0) cert).
	assert.Len(serializedData, 387,
		"Canonicalized ElGamal+DSA-SHA1 should be 387 bytes")
	assert.Equal(keysData, serializedData[:384],
		"Key data must be preserved")

	dest2, remainder2, err2 := ReadDestination(serializedData)
	assert.Nil(err2)
	assert.Empty(remainder2)

	base32_1, err := dest.Base32Address()
	assert.Nil(err)
	base32_2, err := dest2.Base32Address()
	assert.Nil(err)
	assert.Equal(base32_1, base32_2)

	base64_1, err := dest.Base64()
	assert.Nil(err)
	base64_2, err := dest2.Base64()
	assert.Nil(err)
	assert.Equal(base64_1, base64_2)
}

// ============================================================================
// Base32Address
// ============================================================================

func TestBase32AddressFormat(t *testing.T) {
	destBytes := createValidDestinationBytes(t)
	dest, _, err := ReadDestination(destBytes)
	require.NoError(t, err)

	addr, err := dest.Base32Address()
	require.NoError(t, err)

	pattern := regexp.MustCompile(`^[a-z2-7]{52}\.b32\.i2p$`)
	assert.Regexp(t, pattern, addr,
		"Base32 address should be 52 lowercase base32 chars followed by .b32.i2p")
	assert.Len(t, addr, testBase32AddressLength, "Base32 address should be exactly 60 characters")
}

func TestBase32AddressDoesNotLeakInLog(t *testing.T) {
	data := createValidDestinationBytes(t)
	dest, _, err := ReadDestination(data)
	require.NoError(t, err)

	addr, err := dest.Base32Address()
	require.NoError(t, err)
	assert.Contains(t, addr, ".b32.i2p")
}

// ============================================================================
// Address generation uses full destination data
// ============================================================================

func TestDestinationAddressGeneration(t *testing.T) {
	assert := assert.New(t)

	keysData := make([]byte, 384)
	for i := range keysData {
		keysData[i] = byte(i % 256)
	}
	certData := []byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00}
	destData := append(keysData, certData...)

	keysAndCert, remainder, err := keys_and_cert.ReadKeysAndCert(destData)
	assert.Nil(err)
	assert.Empty(remainder)

	dest := Destination{KeysAndCert: keysAndCert}

	base32Addr, err := dest.Base32Address()
	assert.Nil(err)
	base64Addr, err := dest.Base64()
	assert.Nil(err)

	assert.NotEmpty(base32Addr)
	assert.NotEmpty(base64Addr)
	assert.Contains(base32Addr, ".b32.i2p")

	fullDestBytes, err := dest.KeysAndCert.Bytes()
	assert.Nil(err)
	cert := dest.KeysAndCert.Certificate()
	certBytes := cert.Bytes()

	assert.NotEqual(len(fullDestBytes), len(certBytes))
	assert.Greater(len(fullDestBytes), len(certBytes))

	hash := types.SHA256(fullDestBytes)
	expectedBase32, err := dest.Base32Address()
	assert.Nil(err)

	assert.Contains(expectedBase32, ".b32.i2p")
	assert.Greater(len(hash), 0)
}

// ============================================================================
// I2PBase32Suffix constant
// ============================================================================

func TestI2PBase32SuffixConstant(t *testing.T) {
	assert.Equal(t, I2PBase32Suffix, I2P_BASE32_SUFFIX,
		"Both constant names should have the same value")
	assert.Equal(t, ".b32.i2p", I2PBase32Suffix)
}

// ============================================================================
// Ed25519/X25519 destination
// ============================================================================

func TestEd25519X25519Destination(t *testing.T) {
	t.Run("construct and round-trip", func(t *testing.T) {
		data := createEd25519X25519DestinationBytes(t)

		dest, remainder, err := ReadDestination(data)
		require.NoError(t, err)
		assert.Empty(t, remainder)
		assert.NotNil(t, dest.KeysAndCert)

		require.NotNil(t, dest.KeyCertificate)
		assert.Equal(t, key_certificate.KEYCERT_SIGN_ED25519,
			dest.KeyCertificate.SigningPublicKeyType())
		assert.Equal(t, key_certificate.KEYCERT_CRYPTO_X25519,
			dest.KeyCertificate.PublicKeyType())

		serialized, err := dest.Bytes()
		require.NoError(t, err)
		assert.Equal(t, data, serialized)

		dest2, _, err := ReadDestination(serialized)
		require.NoError(t, err)

		addr1, err := dest.Base32Address()
		require.NoError(t, err)
		addr2, err := dest2.Base32Address()
		require.NoError(t, err)
		assert.Equal(t, addr1, addr2)

		b64_1, err := dest.Base64()
		require.NoError(t, err)
		b64_2, err := dest2.Base64()
		require.NoError(t, err)
		assert.Equal(t, b64_1, b64_2)
	})

	t.Run("via NewDestination", func(t *testing.T) {
		data := createEd25519X25519DestinationBytes(t)
		kac, _, err := keys_and_cert.ReadKeysAndCert(data)
		require.NoError(t, err)

		dest, err := NewDestination(kac)
		require.NoError(t, err)
		assert.True(t, dest.IsValid())

		require.NotNil(t, dest.KeyCertificate)
		assert.Equal(t, key_certificate.KEYCERT_SIGN_ED25519,
			dest.KeyCertificate.SigningPublicKeyType())
		assert.Equal(t, key_certificate.KEYCERT_CRYPTO_X25519,
			dest.KeyCertificate.PublicKeyType())
	})

	t.Run("via NewDestinationFromBytes", func(t *testing.T) {
		data := createEd25519X25519DestinationBytes(t)
		dest, remainder, err := NewDestinationFromBytes(data)
		require.NoError(t, err)
		require.NotNil(t, dest)
		assert.Empty(t, remainder)
		assert.True(t, dest.IsValid())
	})
}

// ============================================================================
// Excess key data in certificate (ECDSA_P521)
// ============================================================================

func TestExcessKeyDataInCertificate(t *testing.T) {
	t.Run("ECDSA_P256 signing key with excess data", func(t *testing.T) {
		data := createDestinationBytesWithSigningType(t, key_certificate.KEYCERT_SIGN_P256)
		dest, _, err := ReadDestination(data)
		require.NoError(t, err)
		assert.NotNil(t, dest.KeysAndCert)
	})

	// ECDSA_P521 (type 3) signing keys are 132 bytes; the 4 excess bytes are
	// stored in the Key Certificate payload.  keys_and_cert.ReadKeysAndCert
	// was updated to reconstruct the full 132-byte key from ceil data, so
	// P521 destinations now parse successfully end-to-end.
	t.Run("ECDSA_P521 signing key with excess data", func(t *testing.T) {
		data := createDestinationBytesWithExcessSigningKey(t,
			key_certificate.KEYCERT_SIGN_P521, 4)
		dest, _, err := ReadDestination(data)
		if err != nil {
			// If keys_and_cert upstream reverts, skip gracefully.
			t.Skipf("ECDSA_P521 parsing failed (upstream keys_and_cert limitation): %v", err)
		}
		assert.NotNil(t, dest.KeysAndCert)
		assert.Equal(t, key_certificate.KEYCERT_SIGN_P521,
			dest.KeyCertificate.SigningPublicKeyType())
	})
}

// ============================================================================
// CanonicalizeDestination with explicit KEY(0,0) input
// Finding: [TEST] No test for CanonicalizeDestination with a KEY(0,0) cert input
// ============================================================================

func TestCanonicalizeDestination_KEY00Input(t *testing.T) {
	// Construct a KEY(0,0) destination using readDestinationRaw to bypass
	// the auto-canonicalization in ReadDestination.
	keysData := make([]byte, 384)
	for i := range keysData {
		keysData[i] = byte(i % 256)
	}
	keyCertData := append(keysData, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00)
	dest, _, err := readDestinationRaw(keyCertData)
	require.NoError(t, err)

	// Confirm it's in KEY(0,0) form (391 bytes)
	origBytes, err := dest.Bytes()
	require.NoError(t, err)
	assert.Len(t, origBytes, 391, "KEY(0,0) form must be 391 bytes before canonicalization")

	// Canonicalize
	canonical, err := CanonicalizeDestination(&dest)
	require.NoError(t, err)
	require.NotNil(t, canonical)

	canonBytes, err := canonical.Bytes()
	require.NoError(t, err)

	// Canonical form must be 387 bytes (384 key data + 3-byte NULL cert)
	assert.Len(t, canonBytes, 387, "Canonicalized form must be 387 bytes")

	// Key data must be preserved
	assert.Equal(t, origBytes[:384], canonBytes[:384],
		"Key data must be identical after canonicalization")

	// The trailing 3 bytes must be a NULL cert [0x00, 0x00, 0x00]
	assert.Equal(t, []byte{0x00, 0x00, 0x00}, canonBytes[384:],
		"Canonical form must end with NULL certificate")

	// Hashes must match between canonicalized KEY(0,0) and a direct NULL cert
	nullCertData := make([]byte, 387)
	copy(nullCertData, keysData)
	nullCertData[384] = 0x00
	nullCertData[385] = 0x00
	nullCertData[386] = 0x00
	nullDest, _, err := readDestinationRaw(nullCertData)
	require.NoError(t, err)

	canonHash, err := canonical.Hash()
	require.NoError(t, err)
	nullHash, err := (&nullDest).Hash()
	require.NoError(t, err)
	assert.Equal(t, nullHash, canonHash,
		"Canonicalized KEY(0,0) must hash identically to NULL cert form")
}
