package lease

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLease2IsExpired verifies IsExpired() for Lease2.
func TestLease2IsExpired(t *testing.T) {
	gateway := createTestHash(t, "l2_is_expired_gw_hash___32_bytes")

	futureLease, err := NewLease2(gateway, 1, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.False(t, futureLease.IsExpired())

	pastLease, err := NewLease2(gateway, 1, time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	assert.True(t, pastLease.IsExpired())
}

// TestLease2Equal verifies byte-for-byte equality for Lease2.
func TestLease2Equal(t *testing.T) {
	gateway := createTestHash(t, "l2_equal_test_gw_hash___32_bytes")
	expTime := time.Now().Add(1 * time.Hour)

	lease1, err := NewLease2(gateway, 42, expTime)
	require.NoError(t, err)
	lease2, err := NewLease2(gateway, 42, expTime)
	require.NoError(t, err)
	assert.True(t, lease1.Equal(*lease2))

	lease3, err := NewLease2(gateway, 43, expTime)
	require.NoError(t, err)
	assert.False(t, lease1.Equal(*lease3))
}

// TestLease2Validate verifies Validate() catches semantic issues for Lease2.
func TestLease2Validate(t *testing.T) {
	gateway := createTestHash(t, "l2_validate_test_gw_hash32_bytes")

	valid, err := NewLease2(gateway, 1, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.NoError(t, valid.Validate())

	zeroHash, err := NewLease2(data.Hash{}, 1, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.ErrorIs(t, zeroHash.Validate(), ErrZeroGatewayHash)

	expired, err := NewLease2(gateway, 1, time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	assert.ErrorIs(t, expired.Validate(), ErrExpiredLease)

	both, err := NewLease2(data.Hash{}, 1, time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	assert.ErrorIs(t, both.Validate(), ErrZeroGatewayHash)
}

// TestNewLease2AcceptsExpiredTime verifies that NewLease2 accepts past expiration times.
func TestNewLease2AcceptsExpiredTime(t *testing.T) {
	gateway := createTestHash(t, "l2_past_time_gw_hash____32_bytes")
	pastTime := time.Now().Add(-1 * time.Hour)

	lease2, err := NewLease2(gateway, 1, pastTime)
	require.NoError(t, err, "NewLease2 should accept past expiration times")
	require.NotNil(t, lease2)
	assert.True(t, lease2.IsExpired())
	assert.ErrorIs(t, lease2.Validate(), ErrExpiredLease)
}

// TestNewLease2AcceptsZeroGatewayHash verifies that NewLease2 accepts a zero hash.
func TestNewLease2AcceptsZeroGatewayHash(t *testing.T) {
	zeroHash := data.Hash{}
	futureTime := time.Now().Add(1 * time.Hour)

	lease2, err := NewLease2(zeroHash, 1, futureTime)
	require.NoError(t, err, "NewLease2 should accept zero gateway hash")
	require.NotNil(t, lease2)
	assert.ErrorIs(t, lease2.Validate(), ErrZeroGatewayHash)
}

// TestNewLease2TimestampOverflow verifies that NewLease2 rejects timestamps
// that exceed uint32 seconds (year ~2106).
func TestNewLease2TimestampOverflow(t *testing.T) {
	gateway := createTestHash(t, "l2_overflow_gw_hash_____32_bytes")
	overflowTime := time.Unix(int64(LEASE2_MAX_END_DATE)+1, 0)

	lease2, err := NewLease2(gateway, 1, overflowTime)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrTimestampOverflow)
	assert.Nil(t, lease2)
}

// TestLease2TimestampRolloverBoundary verifies behavior at the uint32 boundary.
func TestLease2TimestampRolloverBoundary(t *testing.T) {
	gateway := createTestHash(t, "l2_rollover_gw_hash_____32_bytes")
	maxUint32Sec := int64(LEASE2_MAX_END_DATE)

	justUnder := time.Unix(maxUint32Sec, 0)
	lease2, err := NewLease2(gateway, 1, justUnder)
	require.NoError(t, err, "should accept timestamp at max uint32")
	assert.Equal(t, uint32(maxUint32Sec), lease2.EndDate())

	justOver := time.Unix(maxUint32Sec+1, 0)
	_, err = NewLease2(gateway, 1, justOver)
	assert.ErrorIs(t, err, ErrTimestampOverflow)

	// Verify via raw construction that max works
	var raw Lease2
	copy(raw[:LEASE_TUNNEL_GW_SIZE], gateway[:])
	binary.BigEndian.PutUint32(raw[LEASE_TUNNEL_GW_SIZE:], 1)
	binary.BigEndian.PutUint32(raw[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], 0xFFFFFFFF)
	assert.Equal(t, uint32(0xFFFFFFFF), raw.EndDate())
}

// TestReadLease2InsufficientData verifies error on short input.
func TestReadLease2InsufficientData(t *testing.T) {
	shortData := make([]byte, LEASE2_SIZE-1)
	_, _, err := ReadLease2(shortData)
	assert.Error(t, err)
}

// TestReadLease2ExactSize verifies correct parsing with exact-size input.
func TestReadLease2ExactSize(t *testing.T) {
	gateway := createTestHash(t, "l2_exact_size_gw_hash___32_bytes")
	lease2, err := NewLease2(gateway, 1, time.Now().Add(10*time.Minute))
	require.NoError(t, err)

	parsed, remainder, err := ReadLease2(lease2.Bytes())
	require.NoError(t, err)
	assert.Empty(t, remainder)
	assert.True(t, lease2.Equal(parsed))
}

// TestReadLease2NilInput verifies error on nil input.
func TestReadLease2NilInput(t *testing.T) {
	_, _, err := ReadLease2(nil)
	assert.Error(t, err)
}

// TestNewLease2FromBytesNilInput verifies error on nil input.
func TestNewLease2FromBytesNilInput(t *testing.T) {
	_, _, err := NewLease2FromBytes(nil)
	assert.Error(t, err)
}

// TestNewLease2FromBytesInsufficientData verifies error on short input.
func TestNewLease2FromBytesInsufficientData(t *testing.T) {
	shortData := make([]byte, LEASE2_SIZE-1)
	_, _, err := NewLease2FromBytes(shortData)
	assert.Error(t, err)
}
