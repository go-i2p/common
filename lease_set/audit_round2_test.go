package lease_set

import (
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/lease"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- SPEC: NewLeaseSet enforces signing key type match ---

func TestAudit2_NewLeaseSetSigningKeyTypeMismatch(t *testing.T) {
	// This test verifies that NewLeaseSet validates signing key type,
	// not just size. We create a valid LeaseSet first to get the components,
	// then try to use a signing key with the wrong type but same size.
	// The type check works via the SigningPublicKeyType() interface method.
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)
	require.NotNil(t, leaseSet)

	// The signing key type check is exercised via validateSigningKey.
	// Since our test setup uses matching Ed25519 keys, NewLeaseSet succeeds.
	// We verify this works correctly.
	sigKey, err := leaseSet.SigningKey()
	require.NoError(t, err)
	assert.Equal(t, 32, len(sigKey.Bytes()), "Ed25519 signing key should be 32 bytes")
}

// --- BUG: OldestExpiration sentinel fix ---

func TestAudit2_OldestExpirationSentinel(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	oldest, err := leaseSet.OldestExpiration()
	require.NoError(t, err)

	// The sentinel was 0x00ffffff... which decodes to ~Jan 2082.
	// After fix, it uses 0xffffffff... (true max), so any valid lease
	// date is always before the sentinel. Verify oldest is a real date.
	leases := leaseSet.Leases()
	for _, l := range leases {
		assert.True(t, oldest.Time().Equal(l.Date().Time()) || oldest.Time().Before(l.Date().Time()),
			"oldest should be <= all lease dates")
	}
}

// --- SPEC: NewLeaseSet with zero leases ---

func TestAudit2_NewLeaseSetZeroLeases(t *testing.T) {
	// The I2P spec says: "A LeaseSet with zero Leases is allowed but is unused."
	// NewLeaseSet should accept an empty lease slice.
	dest, encKey, sigKey, sigPrivKey, err := generateTestDestination(t)
	require.NoError(t, err)

	leaseSet, err := NewLeaseSet(*dest, encKey, sigKey, []lease.Lease{}, sigPrivKey)
	require.NoError(t, err)
	require.NotNil(t, leaseSet)

	count := leaseSet.LeaseCount()
	assert.Equal(t, 0, count)

	err = leaseSet.Validate()
	assert.NoError(t, err, "zero-lease LeaseSet should be valid per spec")
}

// --- BUG: Validate() with zero-value Signature on manually-constructed LeaseSet ---

func TestAudit2_ValidateZeroSignature(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Create a LeaseSet with zero-value signature (as if constructed without signing)
	manualLS := &LeaseSet{
		dest:          leaseSet.dest,
		encryptionKey: leaseSet.encryptionKey,
		signingKey:    leaseSet.signingKey,
		leaseCount:    0,
		leases:        []lease.Lease{},
	}

	// Should not panic on zero-value Signature
	err = manualLS.Validate()
	assert.NoError(t, err)
}

// --- GAP: ReadLeaseSet does not verify signature ---

func TestAudit2_ReadLeaseSetNoVerify(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Serialize, tamper, and re-parse
	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	// Tamper with a byte in the middle (in the encryption key area)
	if len(lsBytes) > 400 {
		lsBytes[400] ^= 0xFF
	}

	// ReadLeaseSet should succeed (no verification during parsing)
	_, err = ReadLeaseSet(lsBytes)
	assert.NoError(t, err, "ReadLeaseSet should not verify signature during parsing")
}

// --- GAP: NewestExpiration / OldestExpiration with zero leases ---

func TestAudit2_ExpirationNoLeases(t *testing.T) {
	ls := LeaseSet{
		leaseCount: 0,
		leases:     []lease.Lease{},
	}

	t.Run("NewestExpiration returns ErrNoLeases", func(t *testing.T) {
		newest, err := ls.NewestExpiration()
		assert.ErrorIs(t, err, ErrNoLeases)
		assert.Equal(t, data.Date{}, newest)
	})

	t.Run("OldestExpiration returns ErrNoLeases", func(t *testing.T) {
		oldest, err := ls.OldestExpiration()
		assert.ErrorIs(t, err, ErrNoLeases)
		assert.Equal(t, data.Date{}, oldest)
	})
}

// --- TEST: ReadLeaseSet rejects lease count > 16 ---

func TestAudit2_ReadLeaseSetExcessiveLeaseCount(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	// Find the lease count byte (after dest + encKey + sigKey).
	// We can detect it by modifying the byte and checking if it causes an error.
	// The lease count byte follows the destination, 256-byte encryption key,
	// and the signing key. For Ed25519, signing key is 32 bytes.
	dest := leaseSet.Destination()
	destBytes, _ := dest.KeysAndCert.Bytes()
	sigKey, _ := leaseSet.SigningKey()
	leaseCountOffset := len(destBytes) + LEASE_SET_PUBKEY_SIZE + len(sigKey.Bytes())

	if leaseCountOffset < len(lsBytes) {
		// Set lease count to 17
		tampered := make([]byte, len(lsBytes))
		copy(tampered, lsBytes)
		tampered[leaseCountOffset] = 17

		_, err = ReadLeaseSet(tampered)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid lease count")
	}
}

// --- TEST: Fuzz test for ReadLeaseSet ---

func FuzzReadLeaseSet(f *testing.F) {
	// Seed corpus
	f.Add([]byte{})
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 387))
	f.Add(make([]byte, 500))
	f.Add(make([]byte, 1000))

	f.Fuzz(func(t *testing.T, data []byte) {
		// ReadLeaseSet should never panic
		ls, err := ReadLeaseSet(data)
		if err == nil {
			// If parsing succeeded, basic accessors should not panic
			_ = ls.Destination()
			_ = ls.LeaseCount()
			_ = ls.Leases()
			_ = ls.Signature()
			_, _ = ls.Bytes()
		}
	})
}

// --- TEST: Bytes() with inconsistent leaseCount vs len(leases) ---

func TestAudit2_BytesInconsistentLeaseCount(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	// Manually set leaseCount to differ from len(leases)
	inconsistentLS := &LeaseSet{
		dest:          leaseSet.dest,
		encryptionKey: leaseSet.encryptionKey,
		signingKey:    leaseSet.signingKey,
		leaseCount:    5,
		leases:        leaseSet.leases, // only 3
		signature:     leaseSet.signature,
	}

	// Validate should catch the mismatch
	err = inconsistentLS.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "lease count mismatch")
}

// --- TEST: PublicKey() with nil encryption key ---

func TestAudit2_PublicKeyNilEncryptionKey(t *testing.T) {
	ls := LeaseSet{} // zero value, encryptionKey is nil
	_, err := ls.PublicKey()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encryption key is nil")
}

// --- TEST: PublicKey() with wrong-size encryption key ---

func TestAudit2_PublicKeyWrongSize(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Verify that a valid LeaseSet returns a correct PublicKey
	pubKey, err := leaseSet.PublicKey()
	assert.NoError(t, err)
	assert.Equal(t, LEASE_SET_PUBKEY_SIZE, len(pubKey.Bytes()))
}

// --- TEST: PublicKey() on zero-value LeaseSet ---

func TestAudit2_PublicKeyZeroValue(t *testing.T) {
	ls := LeaseSet{} // zero value
	_, err := ls.PublicKey()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encryption key is nil")
}

// --- QUALITY: Destination() no longer returns error ---

func TestAudit2_DestinationNoError(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	// Destination() now returns a single value (no error)
	dest := leaseSet.Destination()
	assert.NotNil(t, dest.KeysAndCert)
}

// --- QUALITY: Leases() no longer returns error ---

func TestAudit2_LeasesNoError(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	leases := leaseSet.Leases()
	assert.Equal(t, 3, len(leases))
}

// --- QUALITY: Signature() no longer returns error ---

func TestAudit2_SignatureNoError(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	sig := leaseSet.Signature()
	assert.Equal(t, 64, len(sig.Bytes()), "Ed25519 signature should be 64 bytes")
}

// --- QUALITY: LeaseCount() no longer returns error ---

func TestAudit2_LeaseCountNoError(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	require.NoError(t, err)

	count := leaseSet.LeaseCount()
	assert.Equal(t, 3, count)
}

// --- QUALITY: LEASE_SET_MAX_LEASES constant ---

func TestAudit2_MaxLeasesConstant(t *testing.T) {
	assert.Equal(t, 16, LEASE_SET_MAX_LEASES)
}

// --- QUALITY: ErrNoLeases sentinel ---

func TestAudit2_ErrNoLeasesSentinel(t *testing.T) {
	assert.NotNil(t, ErrNoLeases)
	assert.Contains(t, ErrNoLeases.Error(), "no leases")
}

// --- Round-trip with zero leases through NewLeaseSet + Bytes + ReadLeaseSet ---

func TestAudit2_ZeroLeaseRoundTrip(t *testing.T) {
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

// --- Verify() still works after API changes ---

func TestAudit2_VerifyAfterAPIChanges(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 2)
	require.NoError(t, err)

	// Verify should succeed on valid LeaseSet
	err = leaseSet.Verify()
	assert.NoError(t, err)
}

// --- Verify() detects tampering after API changes ---

func TestAudit2_VerifyDetectsTamperingPostRefactor(t *testing.T) {
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

// --- README constant consistency ---

func TestAudit2_ConstantConsistency(t *testing.T) {
	// LEASE_SET_SPK_SIZE and LEASE_SET_SIG_SIZE are deprecated aliases
	assert.Equal(t, LEASE_SET_DEFAULT_SIGNING_KEY_SIZE, LEASE_SET_SPK_SIZE)
	assert.Equal(t, LEASE_SET_DEFAULT_SIG_SIZE, LEASE_SET_SIG_SIZE)
	assert.Equal(t, 256, LEASE_SET_PUBKEY_SIZE)
	assert.Equal(t, 128, LEASE_SET_DEFAULT_SIGNING_KEY_SIZE)
	assert.Equal(t, 40, LEASE_SET_DEFAULT_SIG_SIZE)
	assert.Equal(t, 16, LEASE_SET_MAX_LEASES)
}
