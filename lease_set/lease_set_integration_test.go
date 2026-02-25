package lease_set

import (
	"crypto/sha256"
	"testing"

	"github.com/go-i2p/common/lease"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Round-trip: NewLeaseSet -> Bytes -> ReadLeaseSet ---

func TestIntegration_RoundTripSingle(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	parsed, err := ReadLeaseSet(lsBytes)
	require.NoError(t, err)

	assert.Equal(t, leaseSet.LeaseCount(), parsed.LeaseCount())

	origLeases := leaseSet.Leases()
	parsedLeases := parsed.Leases()
	assert.Equal(t, len(origLeases), len(parsedLeases))
}

func TestIntegration_RoundTripMultiple(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	parsed, err := ReadLeaseSet(lsBytes)
	require.NoError(t, err)

	assert.Equal(t, leaseSet.LeaseCount(), parsed.LeaseCount())
	assert.Equal(t, len(leaseSet.Leases()), len(parsed.Leases()))
}

func TestIntegration_ZeroLeaseRoundTrip(t *testing.T) {
	dest, encKey, sigKey, sigPrivKey, err := generateTestDestination(t)
	require.NoError(t, err)

	leaseSet, err := NewLeaseSet(*dest, encKey, sigKey, []lease.Lease{}, sigPrivKey)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	parsed, err := ReadLeaseSet(lsBytes)
	require.NoError(t, err)

	assert.Equal(t, 0, parsed.LeaseCount())
	assert.Empty(t, parsed.Leases())
}

// --- Verify cryptographic signature ---

func TestIntegration_VerifyCryptographic(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	err = leaseSet.Verify()
	assert.NoError(t, err)
}

func TestIntegration_VerifyMultipleLeases(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 2)
	require.NoError(t, err)

	err = leaseSet.Verify()
	assert.NoError(t, err)
}

// --- Verify detects tampering ---

func TestIntegration_VerifyDetectsTampering(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Tamper with lease data
	if len(leaseSet.leases) > 0 {
		leaseSet.leases[0][10] ^= 0xFF
	}

	err = leaseSet.Verify()
	assert.Error(t, err, "Verify should detect tampered lease data")
}

// --- Round-trip byte fidelity ---

func TestIntegration_RoundTripByteFidelity(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 2)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	parsed, err := ReadLeaseSet(lsBytes)
	require.NoError(t, err)

	parsedBytes, err := parsed.Bytes()
	require.NoError(t, err)

	assert.Equal(t, lsBytes, parsedBytes, "round-trip bytes should be identical")
}

// --- Components consistency across round-trip ---

func TestIntegration_ComponentsAfterRoundTrip(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	parsed, err := ReadLeaseSet(lsBytes)
	require.NoError(t, err)

	// PublicKey
	origPubKey, err := leaseSet.PublicKey()
	require.NoError(t, err)
	parsedPubKey, err := parsed.PublicKey()
	require.NoError(t, err)
	assert.Equal(t, origPubKey.Bytes(), parsedPubKey.Bytes())

	// SigningKey
	origSigKey, err := leaseSet.SigningKey()
	require.NoError(t, err)
	parsedSigKey, err := parsed.SigningKey()
	require.NoError(t, err)
	assert.Equal(t, origSigKey.Bytes(), parsedSigKey.Bytes())

	// LeaseCount
	assert.Equal(t, leaseSet.LeaseCount(), parsed.LeaseCount())

	// Signature
	assert.Equal(t, leaseSet.Signature().Bytes(), parsed.Signature().Bytes())
}

// --- Verify round-trip: NewLeaseSet -> Bytes -> ReadLeaseSet -> Verify ---

func TestIntegration_VerifyAfterRoundTrip(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	t.Run("single lease round-trip verify", func(t *testing.T) {
		leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
		require.NoError(t, err)

		lsBytes, err := leaseSet.Bytes()
		require.NoError(t, err)

		parsed, err := ReadLeaseSet(lsBytes)
		require.NoError(t, err)

		err = parsed.Verify()
		assert.NoError(t, err, "signature should verify after round-trip")
	})

	t.Run("multiple leases round-trip verify", func(t *testing.T) {
		leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
		require.NoError(t, err)

		lsBytes, err := leaseSet.Bytes()
		require.NoError(t, err)

		parsed, err := ReadLeaseSet(lsBytes)
		require.NoError(t, err)

		err = parsed.Verify()
		assert.NoError(t, err, "signature should verify after round-trip with multiple leases")
	})

	t.Run("zero leases round-trip verify", func(t *testing.T) {
		dest, encKey, sigKey, sigPrivKey, err := generateTestDestination(t)
		require.NoError(t, err)

		leaseSet, err := NewLeaseSet(*dest, encKey, sigKey, []lease.Lease{}, sigPrivKey)
		require.NoError(t, err)

		lsBytes, err := leaseSet.Bytes()
		require.NoError(t, err)

		parsed, err := ReadLeaseSet(lsBytes)
		require.NoError(t, err)

		err = parsed.Verify()
		assert.NoError(t, err, "signature should verify after round-trip with zero leases")
	})
}

func TestIntegration_VerifyAfterRoundTripDetectsTampering(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 2)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	// Tamper with a byte in the lease data area
	dest := leaseSet.Destination()
	destBytes, err := dest.KeysAndCert.Bytes()
	require.NoError(t, err)
	sigKey, err := leaseSet.SigningKey()
	require.NoError(t, err)

	// offset into first lease
	leaseOffset := len(destBytes) + LEASE_SET_PUBKEY_SIZE + len(sigKey.Bytes()) + 1
	tampered := make([]byte, len(lsBytes))
	copy(tampered, lsBytes)
	if leaseOffset+10 < len(tampered) {
		tampered[leaseOffset+10] ^= 0xFF
	}

	parsed, err := ReadLeaseSet(tampered)
	require.NoError(t, err)

	err = parsed.Verify()
	assert.Error(t, err, "Verify should detect tampered data after round-trip")
}

// --- Encryption key type consistency across construction and parsing ---

func TestIntegration_EncryptionKeyTypeConsistency(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Construction path stores the key
	constructedPubKey, err := leaseSet.PublicKey()
	require.NoError(t, err)

	// Round-trip through parsing
	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	parsed, err := ReadLeaseSet(lsBytes)
	require.NoError(t, err)

	parsedPubKey, err := parsed.PublicKey()
	require.NoError(t, err)

	// Both should produce identical ElGamal keys
	assert.Equal(t, constructedPubKey.Bytes(), parsedPubKey.Bytes(),
		"encryption key should be identical after round-trip")

	// Both should be ElGamal type
	assert.True(t, isElGamalKey(leaseSet.encryptionKey), "constructed key should be ElGamal")
	assert.True(t, isElGamalKey(parsed.encryptionKey), "parsed key should be ElGamal")
}

// --- Parsed signing key size matches certificate ---

func TestIntegration_ParsedSigningKeySizeMatchesCert(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	// Round-trip: signing key size should match cert expectation
	parsed, err := ReadLeaseSet(lsBytes)
	require.NoError(t, err)

	sigKey, err := parsed.SigningKey()
	require.NoError(t, err)

	dest := parsed.Destination()
	cert := dest.Certificate()
	kind, err := cert.Type()
	require.NoError(t, err)

	expectedSize := determineSigningKeySize(cert, kind)
	assert.Equal(t, expectedSize, len(sigKey.Bytes()),
		"parsed signing key size should match certificate-derived size")
}

// --- NewLeaseSet rejects mismatched signing private key (spec: signed by Destination's key) ---

func TestIntegration_NewLeaseSetMismatchedPrivKeyReturnsError(t *testing.T) {
	dest, encKey, sigKey, _, err := generateTestDestination(t)
	require.NoError(t, err)

	// Generate a completely independent destination; grab only its private key.
	_, _, _, mismatchedPrivKey, err2 := generateTestDestination(t)
	require.NoError(t, err2)

	_, newErr := NewLeaseSet(*dest, encKey, sigKey, nil, mismatchedPrivKey)
	require.Error(t, newErr,
		"NewLeaseSet must return an error when the signing private key does not correspond to the destination's signing public key")
}

// --- Hash returns the SHA-256 of the Destination (spec: netdb key) ---

func TestIntegration_HashIsDestinationSHA256(t *testing.T) {
	dest, encKey, sigKey, sigPrivKey, err := generateTestDestination(t)
	require.NoError(t, err)

	leaseSet, err := NewLeaseSet(*dest, encKey, sigKey, []lease.Lease{}, sigPrivKey)
	require.NoError(t, err)

	hash, err := leaseSet.Hash()
	require.NoError(t, err)
	require.Equal(t, 32, len(hash), "hash must be 32 bytes")

	// Hash must equal SHA-256(Destination bytes) per spec.
	destBytes, err := dest.KeysAndCert.Bytes()
	require.NoError(t, err)
	expected := sha256.Sum256(destBytes)
	assert.Equal(t, expected, hash, "Hash must equal SHA-256 of serialized Destination")

	// Must be deterministic across calls.
	hash2, err := leaseSet.Hash()
	require.NoError(t, err)
	assert.Equal(t, hash, hash2, "Hash must be deterministic across calls")
}
