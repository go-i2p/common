package lease_set

import (
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
