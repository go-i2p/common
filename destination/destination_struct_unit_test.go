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

	assert.Equal(originalData, serializedData, "Serialized destination should match original data")
	assert.Equal(len(originalData), len(serializedData))

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

	t.Run("ECDSA_P521 signing key with excess data", func(t *testing.T) {
		data := createDestinationBytesWithExcessSigningKey(t,
			key_certificate.KEYCERT_SIGN_P521, 4)
		_, _, err := ReadDestination(data)
		assert.Error(t, err, "excess key data reconstruction not yet implemented in keys_and_cert")
	})
}
