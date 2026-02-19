package lease

import (
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLeaseIsExpired verifies IsExpired() for both future and past leases.
func TestLeaseIsExpired(t *testing.T) {
	gateway := createTestHash(t, "is_expired_gw_hash______32_bytes")

	futureLease, err := NewLease(gateway, 1, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.False(t, futureLease.IsExpired())

	pastLease, err := NewLease(gateway, 1, time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	assert.True(t, pastLease.IsExpired())
}

// TestLeaseEqual verifies byte-for-byte equality comparison.
func TestLeaseEqual(t *testing.T) {
	gateway := createTestHash(t, "equal_test_gw_hash______32_bytes")
	expTime := time.Now().Add(1 * time.Hour)

	lease1, err := NewLease(gateway, 42, expTime)
	require.NoError(t, err)

	lease2, err := NewLease(gateway, 42, expTime)
	require.NoError(t, err)
	assert.True(t, lease1.Equal(*lease2))

	lease3, err := NewLease(gateway, 43, expTime)
	require.NoError(t, err)
	assert.False(t, lease1.Equal(*lease3))
}

// TestLeaseValidate verifies Validate() catches semantic issues.
func TestLeaseValidate(t *testing.T) {
	gateway := createTestHash(t, "validate_test_gw_hash___32_bytes")

	valid, err := NewLease(gateway, 1, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.NoError(t, valid.Validate())

	zeroHash, err := NewLease(data.Hash{}, 1, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.ErrorIs(t, zeroHash.Validate(), ErrZeroGatewayHash)

	expired, err := NewLease(gateway, 1, time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	assert.ErrorIs(t, expired.Validate(), ErrExpiredLease)

	both, err := NewLease(data.Hash{}, 1, time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	assert.ErrorIs(t, both.Validate(), ErrZeroGatewayHash)
}

// TestNewLeaseAcceptsExpiredTime verifies that NewLease accepts past expiration times.
func TestNewLeaseAcceptsExpiredTime(t *testing.T) {
	gateway := createTestHash(t, "past_time_gateway_hash__32_bytes")
	pastTime := time.Now().Add(-1 * time.Hour)

	lease, err := NewLease(gateway, 1, pastTime)
	require.NoError(t, err, "NewLease should accept past expiration times")
	require.NotNil(t, lease)
	assert.True(t, lease.IsExpired())
	assert.ErrorIs(t, lease.Validate(), ErrExpiredLease)
}

// TestNewLeaseAcceptsZeroGatewayHash verifies that NewLease accepts a zero hash.
func TestNewLeaseAcceptsZeroGatewayHash(t *testing.T) {
	zeroHash := data.Hash{}
	futureTime := time.Now().Add(1 * time.Hour)

	lease, err := NewLease(zeroHash, 1, futureTime)
	require.NoError(t, err, "NewLease should accept zero gateway hash")
	require.NotNil(t, lease)
	assert.ErrorIs(t, lease.Validate(), ErrZeroGatewayHash)
}

// TestReadLeaseErrorMessageFormat verifies error messages include expected/actual byte counts.
func TestReadLeaseErrorMessageFormat(t *testing.T) {
	shortData := make([]byte, 10)
	_, _, err := ReadLease(shortData)
	require.Error(t, err)
	errMsg := err.Error()
	assert.Contains(t, errMsg, "expected 44")
	assert.Contains(t, errMsg, "got 10")
}
