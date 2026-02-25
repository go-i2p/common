package lease

import (
	"encoding/binary"
	"errors"
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

// TestNewLeasePreEpochTimestamp verifies that NewLease rejects pre-epoch times.
func TestNewLeasePreEpochTimestamp(t *testing.T) {
	gateway := createTestHash(t, "pre_epoch_gw_hash_______32_bytes")

	tests := []struct {
		name string
		time time.Time
	}{
		{"just_before_epoch", time.Unix(-1, 0)},
		{"year_1969", time.Date(1969, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"far_past", time.Date(1900, 6, 15, 12, 0, 0, 0, time.UTC)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lease, err := NewLease(gateway, 1, tt.time)
			assert.Error(t, err, "NewLease should reject pre-epoch time %v", tt.time)
			assert.ErrorIs(t, err, ErrPreEpochTimestamp)
			assert.Nil(t, lease)
		})
	}
}

// TestNewLeasePreEpochSymmetryWithLease2 verifies both constructors reject
// pre-epoch times consistently with the same error type.
func TestNewLeasePreEpochSymmetryWithLease2(t *testing.T) {
	gateway := createTestHash(t, "symmetry_gw_hash________32_bytes")
	preEpoch := time.Date(1969, 6, 15, 0, 0, 0, 0, time.UTC)

	_, err1 := NewLease(gateway, 1, preEpoch)
	assert.ErrorIs(t, err1, ErrPreEpochTimestamp,
		"NewLease should reject pre-epoch with ErrPreEpochTimestamp")

	_, err2 := NewLease2(gateway, 1, preEpoch)
	assert.ErrorIs(t, err2, ErrPreEpochTimestamp,
		"NewLease2 should also reject pre-epoch with ErrPreEpochTimestamp")
}

// TestNewLeaseAcceptsEpochExact verifies that time exactly at epoch is accepted.
func TestNewLeaseAcceptsEpochExact(t *testing.T) {
	gateway := createTestHash(t, "epoch_exact_gw_hash_____32_bytes")
	epochTime := time.Unix(0, 0).UTC()

	lease, err := NewLease(gateway, 1, epochTime)
	require.NoError(t, err, "NewLease should accept time exactly at epoch")
	require.NotNil(t, lease)
	assert.Equal(t, uint64(0),
		binary.BigEndian.Uint64(lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:]))
}

// TestLeaseValidateZeroTunnelID verifies Validate() reports zero tunnel ID.
func TestLeaseValidateZeroTunnelID(t *testing.T) {
	gateway := createTestHash(t, "zero_tid_validate_gw____32_bytes")
	lease, err := NewLease(gateway, 0, time.Now().Add(1*time.Hour))
	require.NoError(t, err)

	err = lease.Validate()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrZeroTunnelID)
	assert.False(t, errors.Is(err, ErrZeroGatewayHash))
	assert.False(t, errors.Is(err, ErrExpiredLease))
}

// TestLeaseValidateNonZeroTunnelID verifies valid lease passes with non-zero tunnel ID.
func TestLeaseValidateNonZeroTunnelID(t *testing.T) {
	gateway := createTestHash(t, "nonzero_tid_val_gw_hash_32_bytes")
	lease, err := NewLease(gateway, 42, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.NoError(t, lease.Validate())
}

// TestLeaseValidateMultipleErrors verifies Validate() returns all applicable errors.
func TestLeaseValidateMultipleErrors(t *testing.T) {
	lease, err := NewLease(data.Hash{}, 0, time.Now().Add(-1*time.Hour))
	require.NoError(t, err)

	err = lease.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrZeroGatewayHash, "should contain ErrZeroGatewayHash")
	assert.ErrorIs(t, err, ErrZeroTunnelID, "should contain ErrZeroTunnelID")
	assert.ErrorIs(t, err, ErrExpiredLease, "should contain ErrExpiredLease")
}

// TestLeaseValidateNoErrors verifies Validate() returns nil when all is valid.
func TestLeaseValidateNoErrors(t *testing.T) {
	gateway := createTestHash(t, "all_valid_gw_hash_______32_bytes")
	lease, err := NewLease(gateway, 1, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.NoError(t, lease.Validate())
}

// TestLeaseValidateTwoErrors verifies exactly two errors are reported.
func TestLeaseValidateTwoErrors(t *testing.T) {
	lease, err := NewLease(data.Hash{}, 1, time.Now().Add(-1*time.Hour))
	require.NoError(t, err)

	err = lease.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrZeroGatewayHash)
	assert.ErrorIs(t, err, ErrExpiredLease)
	assert.False(t, errors.Is(err, ErrZeroTunnelID))
}

// TestLeaseValidateNullDateDistinctFromExpired verifies that end_date=0 returns
// ErrNullDate and NOT ErrExpiredLease, per spec "Date == 0 is undefined or null".
func TestLeaseValidateNullDateDistinctFromExpired(t *testing.T) {
	gateway := createTestHash(t, "null_date_gw_hash_______32_bytes")

	// Construct a lease with end_date = 0 directly (epoch time)
	epochTime := time.Unix(0, 0).UTC()
	lease, err := NewLease(gateway, 1, epochTime)
	require.NoError(t, err)
	require.NotNil(t, lease)

	// end_date bytes must be all-zero to confirm the null sentinel was stored
	dateMillis := binary.BigEndian.Uint64(lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:])
	require.Equal(t, uint64(0), dateMillis, "epoch-time lease should encode end_date=0")

	validationErr := lease.Validate()
	require.Error(t, validationErr)
	assert.ErrorIs(t, validationErr, ErrNullDate,
		"end_date=0 must produce ErrNullDate, not ErrExpiredLease")
	assert.False(t, errors.Is(validationErr, ErrExpiredLease),
		"end_date=0 must NOT produce ErrExpiredLease; it is null, not merely expired")
}

// TestLeaseValidateNullDateMultipleErrors verifies ErrNullDate combines with other errors.
func TestLeaseValidateNullDateMultipleErrors(t *testing.T) {
	epochTime := time.Unix(0, 0).UTC()
	lease, err := NewLease(data.Hash{}, 1, epochTime)
	require.NoError(t, err)

	validationErr := lease.Validate()
	require.Error(t, validationErr)
	assert.ErrorIs(t, validationErr, ErrZeroGatewayHash)
	assert.ErrorIs(t, validationErr, ErrNullDate)
	assert.False(t, errors.Is(validationErr, ErrExpiredLease))
}

// TestLeaseDateInt_EpochZeroRoundTrip verifies that a zero end_date round-trips
// through Date().Int() and produces 0, confirming it is the null sentinel.
func TestLeaseDateInt_EpochZeroRoundTrip(t *testing.T) {
	epochTime := time.Unix(0, 0).UTC()
	gateway := createTestHash(t, "date_int_epoch_gw_hash__32_bytes")

	lease, err := NewLease(gateway, 1, epochTime)
	require.NoError(t, err)

	date := lease.Date()
	assert.Equal(t, 0, date.Int(),
		"Date().Int() should return 0 for epoch-zero (null) end_date")
	assert.Equal(t, uint64(0), binary.BigEndian.Uint64(date[:]),
		"raw bytes of Date should be all-zero for epoch-zero end_date")
}
