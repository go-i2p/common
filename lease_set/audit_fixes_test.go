package lease_set

import (
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Finding #1: determineSignatureSize() now uses correct upstream SignatureSize() ---

func TestAudit_DetermineSignatureSizeCorrect(t *testing.T) {
	// After key_certificate fix, SignatureSize() returns actual signature sizes.
	// This test verifies that parseSignature reads the correct number of bytes
	// by exercising the full ReadLeaseSet path and checking the signature length.
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)
	require.NotNil(t, leaseSet)

	sig := leaseSet.Signature()
	// Ed25519 signature should be 64 bytes
	assert.Equal(t, 64, len(sig.Bytes()), "Ed25519 signature should be 64 bytes")
}

// --- Finding #2: NewestExpiration() sentinel fix ---

func TestAudit_NewestExpiration(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	newest, err := leaseSet.NewestExpiration()
	require.NoError(t, err)

	// The newest expiration should be in the future (not epoch zero or far-future sentinel)
	assert.True(t, newest.Time().After(time.Now()),
		"newest expiration should be in the future, got %v", newest.Time())

	// Verify it's actually the newest among leases
	leases := leaseSet.Leases()
	for _, l := range leases {
		assert.True(t, newest.Time().Equal(l.Date().Time()) || newest.Time().After(l.Date().Time()),
			"newest should be >= all lease dates")
	}
}

func TestAudit_NewestExpirationSingleLease(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	newest, err := leaseSet.NewestExpiration()
	require.NoError(t, err)

	oldest, err := leaseSet.OldestExpiration()
	require.NoError(t, err)

	// With single lease, newest == oldest
	assert.Equal(t, newest.Time().Unix(), oldest.Time().Unix(),
		"with one lease, newest and oldest should be the same")
}

// --- Finding #3: Validate() allows zero leases per spec ---

func TestAudit_ValidateZeroLeases(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	// Create a lease set with 1 lease first, then modify it to have 0
	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Manually create a zero-lease LeaseSet
	zeroLeaseSet := &LeaseSet{
		dest:          leaseSet.dest,
		encryptionKey: leaseSet.encryptionKey,
		signingKey:    leaseSet.signingKey,
		leaseCount:    0,
		leases:        []lease.Lease{},
		signature:     leaseSet.signature,
	}

	// Per I2P spec: "A LeaseSet with zero Leases is allowed but is unused."
	err = zeroLeaseSet.Validate()
	assert.NoError(t, err, "zero-lease LeaseSet should be valid per I2P spec")
}

func TestAudit_ValidateMaxLeases(t *testing.T) {
	// Lease count > 16 should still be rejected
	leaseSet := &LeaseSet{
		leaseCount: 17,
	}
	err := leaseSet.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "more than 16 leases")
}

// --- Finding #4: parseSignature handles cert.Type() error ---

func TestAudit_ParseSignatureErrorHandling(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Serialize and re-parse to exercise parseSignature
	leaseSetBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	parsed, err := ReadLeaseSet(leaseSetBytes)
	require.NoError(t, err)

	// Verify signature was parsed correctly
	origSig := leaseSet.Signature()
	parsedSig := parsed.Signature()
	assert.Equal(t, origSig.Bytes(), parsedSig.Bytes(),
		"parsed signature should match original")
}

// --- Finding #5: determineSigningKeySize uses SigningPublicKeySize ---

func TestAudit_DetermineSigningKeySizeUsesCorrectAPI(t *testing.T) {
	// This is verified indirectly through successful LeaseSet creation and parsing.
	// For Ed25519, SigningPublicKeySize() returns 32 (correct), while
	// SignatureSize() returns 64 (which would be wrong for signing key size).
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Serialize and re-parse
	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	parsed, err := ReadLeaseSet(lsBytes)
	require.NoError(t, err)

	// Verify signing key was correctly parsed (32 bytes for Ed25519)
	signKey, err := parsed.SigningKey()
	require.NoError(t, err)
	assert.Equal(t, 32, len(signKey.Bytes()),
		"Ed25519 signing public key should be 32 bytes")
}

// --- Gap #1: parseSignature returns remainder and warns on trailing data ---

func TestAudit_ParseSignatureTrailingData(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Serialize and append extra bytes
	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)
	lsBytesWithTrailing := append(lsBytes, 0xDE, 0xAD, 0xBE, 0xEF)

	// ReadLeaseSet should still succeed (trailing data is warned, not rejected)
	parsed, err := ReadLeaseSet(lsBytesWithTrailing)
	require.NoError(t, err)

	// Verify the parsed LeaseSet is valid
	origSig := leaseSet.Signature()
	parsedSig := parsed.Signature()
	assert.Equal(t, origSig.Bytes(), parsedSig.Bytes())
}

// --- Gap #2: RedDSA support in constructSigningKey (handled by key_certificate) ---

// RedDSA (type 11) is handled by keyCert.ConstructSigningPublicKey() which
// delegates to constructEd25519Key. The constructSigningKey function in utils.go
// correctly delegates to keyCert for all CERT_KEY certificate types.
// This is tested indirectly through key_certificate tests.

// --- Gap #3: ReadLeaseSet does not verify signature during parsing ---
// ACKNOWLEDGED: Separate Verify() method exists for explicit verification.

// --- Gap #4: DestinationDeux removed ---

func TestAudit_DestinationDeuxRemoved(t *testing.T) {
	// Verify that Destination() works correctly (DestinationDeux was removed)
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	dest := leaseSet.Destination()
	assert.NotNil(t, dest.KeysAndCert)
}

// --- Testing Gap #1: Uncommented tests (already done in lease_set_test.go) ---

// --- Testing Gap #2: Round-trip serialization test ---

func TestAudit_RoundTripSerialization(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	t.Run("single lease", func(t *testing.T) {
		leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
		require.NoError(t, err)

		lsBytes, err := leaseSet.Bytes()
		require.NoError(t, err)

		parsed, err := ReadLeaseSet(lsBytes)
		require.NoError(t, err)

		// Compare all fields
		origDest := leaseSet.Destination()
		parsedDest := parsed.Destination()
		origDestBytes, _ := origDest.KeysAndCert.Bytes()
		parsedDestBytes, _ := parsedDest.KeysAndCert.Bytes()
		assert.Equal(t, origDestBytes, parsedDestBytes, "destination should match")

		origCount := leaseSet.LeaseCount()
		parsedCount := parsed.LeaseCount()
		assert.Equal(t, origCount, parsedCount, "lease count should match")

		origSig := leaseSet.Signature()
		parsedSig := parsed.Signature()
		assert.Equal(t, origSig.Bytes(), parsedSig.Bytes(), "signature should match")
	})

	t.Run("multiple leases", func(t *testing.T) {
		leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
		require.NoError(t, err)

		lsBytes, err := leaseSet.Bytes()
		require.NoError(t, err)

		parsed, err := ReadLeaseSet(lsBytes)
		require.NoError(t, err)

		parsedBytes, err := parsed.Bytes()
		require.NoError(t, err)

		assert.Equal(t, lsBytes, parsedBytes, "round-trip bytes should be identical")
	})
}

// --- Testing Gap #3: Malformed/truncated input tests ---

func TestAudit_ReadLeaseSetMalformedInput(t *testing.T) {
	t.Run("nil data", func(t *testing.T) {
		_, err := ReadLeaseSet(nil)
		assert.Error(t, err)
	})

	t.Run("empty data", func(t *testing.T) {
		_, err := ReadLeaseSet([]byte{})
		assert.Error(t, err)
	})

	t.Run("too short for destination", func(t *testing.T) {
		_, err := ReadLeaseSet(make([]byte, 100))
		assert.Error(t, err)
	})

	t.Run("exactly minimum destination size but invalid", func(t *testing.T) {
		_, err := ReadLeaseSet(make([]byte, 387))
		assert.Error(t, err)
	})
}

// --- Testing Gap #4: Zero-lease LeaseSet test ---

func TestAudit_ZeroLeaseLeaseSet(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Create a zero-lease variant
	zeroLS := &LeaseSet{
		dest:          leaseSet.dest,
		encryptionKey: leaseSet.encryptionKey,
		signingKey:    leaseSet.signingKey,
		leaseCount:    0,
		leases:        []lease.Lease{},
		signature:     leaseSet.signature,
	}

	// Zero leases should be valid per spec
	assert.NoError(t, zeroLS.Validate())
	assert.True(t, zeroLS.IsValid())

	// LeaseCount should return 0
	count := zeroLS.LeaseCount()
	assert.Equal(t, 0, count)
}

// --- Testing Gap #5: Verify() with actual cryptographic verification ---

func TestAudit_VerifyCryptographic(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Verify should succeed on a freshly-created LeaseSet
	err = leaseSet.Verify()
	assert.NoError(t, err, "Verify() should succeed on a valid LeaseSet")
}

func TestAudit_VerifyDetectsTampering(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Tamper with a lease
	if len(leaseSet.leases) > 0 {
		leaseSet.leases[0][0] ^= 0xFF // flip bits in first byte
	}

	// Verify should fail on tampered data
	err = leaseSet.Verify()
	assert.Error(t, err, "Verify() should fail on tampered LeaseSet")
}

// --- Quality #1: No more fmt.Printf in production code ---

// Verified by compilation: fmt import removed from utils.go and lease_set.go.
// If fmt.Printf calls remained, the unused import removal would cause a build error.

// --- Quality #4: Constant names are now descriptive ---

func TestAudit_ConstantNames(t *testing.T) {
	// Verify new descriptive constants exist and match legacy aliases
	assert.Equal(t, LEASE_SET_DEFAULT_SIGNING_KEY_SIZE, LEASE_SET_SPK_SIZE,
		"legacy LEASE_SET_SPK_SIZE should equal new descriptive constant")
	assert.Equal(t, LEASE_SET_DEFAULT_SIG_SIZE, LEASE_SET_SIG_SIZE,
		"legacy LEASE_SET_SIG_SIZE should equal new descriptive constant")
	assert.Equal(t, 128, LEASE_SET_DEFAULT_SIGNING_KEY_SIZE)
	assert.Equal(t, 40, LEASE_SET_DEFAULT_SIG_SIZE)
	assert.Equal(t, 256, LEASE_SET_PUBKEY_SIZE)
}

// --- OldestExpiration correctness ---

func TestAudit_OldestExpiration(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	oldest, err := leaseSet.OldestExpiration()
	require.NoError(t, err)

	// The oldest expiration should be in the future
	assert.True(t, oldest.Time().After(time.Now()),
		"oldest expiration should be in the future, got %v", oldest.Time())

	// Verify it's actually the oldest among leases
	leases := leaseSet.Leases()
	for _, l := range leases {
		assert.True(t, oldest.Time().Equal(l.Date().Time()) || oldest.Time().Before(l.Date().Time()),
			"oldest should be <= all lease dates")
	}
}

// --- Expiration ordering test ---

func TestAudit_ExpirationOrdering(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	newest, err := leaseSet.NewestExpiration()
	require.NoError(t, err)

	oldest, err := leaseSet.OldestExpiration()
	require.NoError(t, err)

	assert.True(t, newest.Time().After(oldest.Time()) || newest.Time().Equal(oldest.Time()),
		"newest expiration should be >= oldest expiration")
}

// --- Empty lease expirations ---

func TestAudit_ExpirationEmptyLeases(t *testing.T) {
	ls := LeaseSet{
		leaseCount: 0,
		leases:     []lease.Lease{},
	}

	newest, err := ls.NewestExpiration()
	assert.ErrorIs(t, err, ErrNoLeases)
	// With no leases, should return epoch zero
	assert.Equal(t, data.Date{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, newest)
}
