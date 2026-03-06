package lease_set

import (
	"errors"
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/lease"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- NewLeaseSet rejects too many leases ---

func TestValidation_TooManyLeases(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	_, err = createTestLeaseSet(t, routerInfo, 17)
	require.Error(t, err)
	assert.Equal(t, "invalid lease set: more than 16 leases", err.Error())
}

// --- Validate detects zero leases (should succeed per spec) ---

func TestValidation_ValidateZeroLeases(t *testing.T) {
	dest, encKey, sigKey, sigPrivKey, err := generateTestDestination(t)
	require.NoError(t, err)

	leaseSet, err := NewLeaseSet(*dest, encKey, sigKey, []lease.Lease{}, sigPrivKey)
	require.NoError(t, err)

	err = leaseSet.Validate()
	assert.NoError(t, err, "zero leases should be valid per spec")
}

// --- Validate detects max leases ---

func TestValidation_ValidateMaxLeases(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 16)
	require.NoError(t, err)

	err = leaseSet.Validate()
	assert.NoError(t, err, "16 leases (max) should be valid")
}

// --- ReadLeaseSet with malformed input ---

func TestValidation_ReadLeaseSetMalformedInput(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		_, err := ReadLeaseSet(nil)
		assert.Error(t, err)
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := ReadLeaseSet([]byte{})
		assert.Error(t, err)
	})

	t.Run("short input", func(t *testing.T) {
		_, err := ReadLeaseSet(make([]byte, 100))
		assert.Error(t, err)
	})

	t.Run("exact minimum size", func(t *testing.T) {
		_, err := ReadLeaseSet(make([]byte, 387))
		assert.Error(t, err)
	})
}

// --- ReadLeaseSet with excessive lease count ---

func TestValidation_ReadLeaseSetExcessiveLeaseCount(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	dest := leaseSet.Destination()
	destBytes, _ := dest.KeysAndCert.Bytes()
	sigKey, _ := leaseSet.SigningKey()
	leaseCountOffset := len(destBytes) + LEASE_SET_PUBKEY_SIZE + len(sigKey.Bytes())

	if leaseCountOffset < len(lsBytes) {
		tampered := make([]byte, len(lsBytes))
		copy(tampered, lsBytes)
		tampered[leaseCountOffset] = 17

		_, err = ReadLeaseSet(tampered)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid lease count")
	}
}

// --- ReadLeaseSet does not verify signature ---

func TestValidation_ReadLeaseSetNoVerify(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	// Tamper with a byte in the encryption key area
	if len(lsBytes) > 400 {
		lsBytes[400] ^= 0xFF
	}

	// ReadLeaseSet should succeed (no verification during parsing)
	_, err = ReadLeaseSet(lsBytes)
	assert.NoError(t, err, "ReadLeaseSet should not verify signature during parsing")
}

// --- ParseSignature error handling ---

func TestValidation_ParseSignatureErrorHandling(t *testing.T) {
	// parseSignature needs a destination.Destination with a valid certificate
	// to determine signature size. With a zero-value dest and short data,
	// it should return an error.
	dest, _, _, _, err := generateTestDestination(t)
	require.NoError(t, err)

	shortData := make([]byte, 5)
	_, _, err = parseSignature(shortData, *dest)
	assert.Error(t, err)
}

// --- ParseSignature trailing data ---

func TestValidation_ParseSignatureTrailingData(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	// Add trailing data
	withTrailing := append(lsBytes, []byte{0xDE, 0xAD, 0xBE, 0xEF}...)

	// ReadLeaseSet should reject trailing data per spec
	_, err = ReadLeaseSet(withTrailing)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrTrailingData)
}

// --- Trailing data rejection (subtests) ---

func TestValidation_TrailingDataRejected(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	t.Run("single trailing byte rejected", func(t *testing.T) {
		withTrailing := append(append([]byte{}, lsBytes...), 0x00)
		_, err := ReadLeaseSet(withTrailing)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrTrailingData), "expected ErrTrailingData, got: %v", err)
	})

	t.Run("multiple trailing bytes rejected", func(t *testing.T) {
		withTrailing := append(append([]byte{}, lsBytes...), 0xDE, 0xAD, 0xBE, 0xEF)
		_, err := ReadLeaseSet(withTrailing)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrTrailingData), "expected ErrTrailingData, got: %v", err)
	})

	t.Run("exact bytes accepted", func(t *testing.T) {
		parsed, err := ReadLeaseSet(lsBytes)
		assert.NoError(t, err)
		assert.Equal(t, leaseSet.LeaseCount(), parsed.LeaseCount())
	})
}

func TestValidation_TrailingDataWithMultipleLeases(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	withTrailing := append(append([]byte{}, lsBytes...), 0xFF)
	_, err = ReadLeaseSet(withTrailing)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrailingData))
}

// --- Validate detects all-zero encryption key ---

func TestValidation_ValidateRejectsAllZeroEncryptionKey(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	var zeroKey elgamal.ElgPublicKey // all zeros
	manualLS := &LeaseSet{
		dest:          leaseSet.dest,
		encryptionKey: zeroKey,
		signingKey:    leaseSet.signingKey,
		leaseCount:    0,
		leases:        []lease.Lease{},
	}

	err = manualLS.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAllZeroEncryptionKey),
		"expected ErrAllZeroEncryptionKey, got: %v", err)
}

func TestValidation_ValidateAcceptsNonZeroEncryptionKey(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	err = leaseSet.Validate()
	assert.NoError(t, err)
}

func TestValidation_ReadLeaseSetAllZeroEncryptionKeyFailsValidation(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	dest := leaseSet.Destination()
	destBytes, err := dest.KeysAndCert.Bytes()
	require.NoError(t, err)
	destLen := len(destBytes)

	tampered := make([]byte, len(lsBytes))
	copy(tampered, lsBytes)
	for i := destLen; i < destLen+LEASE_SET_PUBKEY_SIZE; i++ {
		tampered[i] = 0x00
	}

	// ReadLeaseSet rejects all-zero ElGamal key at parse time
	_, err = ReadLeaseSet(tampered)
	assert.Error(t, err, "ReadLeaseSet should reject all-zero ElGamal key")

	// Also test Validate() on a directly-constructed LeaseSet with zero key
	var zeroKey elgamal.ElgPublicKey
	manualLS := &LeaseSet{
		dest:          leaseSet.dest,
		encryptionKey: zeroKey,
		signingKey:    leaseSet.signingKey,
		leaseCount:    0,
		leases:        []lease.Lease{},
	}
	err = manualLS.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAllZeroEncryptionKey))
}

// --- Validate checks ElGamal type (not just size) ---

func TestValidation_ValidateRejectsNonElGamalEncryptionKey(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Substitute a non-ElGamal 256-byte key
	var fakeKey mockNonElGamalKey
	fakeKey[0] = 0x01 // non-zero so it passes the all-zero check
	manualLS := &LeaseSet{
		dest:          leaseSet.dest,
		encryptionKey: fakeKey,
		signingKey:    leaseSet.signingKey,
		leaseCount:    leaseSet.leaseCount,
		leases:        leaseSet.leases,
		signature:     leaseSet.signature,
	}

	err = manualLS.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNonElGamalEncryptionKey,
		"Validate() must reject non-ElGamal encryption keys")
}

// --- Validate checks signing key size against certificate ---

func TestValidation_ValidateChecksSigningKeySize(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Replace signing key with a wrong-sized key
	wrongSizeKey := mockSigningKey(make([]byte, 64)) // Ed25519 key should be 32 bytes
	manualLS := &LeaseSet{
		dest:          leaseSet.dest,
		encryptionKey: leaseSet.encryptionKey,
		signingKey:    wrongSizeKey,
		leaseCount:    leaseSet.leaseCount,
		leases:        leaseSet.leases,
		signature:     leaseSet.signature,
	}

	err = manualLS.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSigningKeySizeMismatch,
		"Validate() must reject signing keys with wrong size for certificate")
}

func TestValidation_ValidateAcceptsCorrectSigningKeySize(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Valid LeaseSet should pass
	err = leaseSet.Validate()
	assert.NoError(t, err, "valid LeaseSet with correct signing key size should pass Validate()")
}

// --- validateNullCertSigningKey rejects legacy crypto ---

func TestValidation_NullCertSigningKeyRejectsLegacy(t *testing.T) {
	dest, _, sigKey, _, err := generateTestDestination(t)
	require.NoError(t, err)

	// Override dest certificate to NULL (DSA-SHA1)
	oldCert := dest.Certificate()
	nullCert, err := certificate.NewCertificateWithType(certificate.CERT_NULL, nil)
	require.NoError(t, err)
	_ = oldCert
	_ = nullCert

	// validateNullCertSigningKey should reject regardless of key
	err = validateNullCertSigningKey(sigKey)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrLegacyCryptoNotSupported)

	// Also reject even with correct 128-byte DSA-sized key
	dsaSizedKey := mockSigningKey(make([]byte, 128))
	err = validateNullCertSigningKey(dsaSizedKey)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrLegacyCryptoNotSupported)
}
