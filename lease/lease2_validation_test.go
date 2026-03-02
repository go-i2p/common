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

// TestLease2ValidateZeroTunnelID verifies Validate() reports zero tunnel ID for Lease2.
func TestLease2ValidateZeroTunnelID(t *testing.T) {
	gateway := createTestHash(t, "l2_zero_tid_validate_gw_32_bytes")
	lease2, err := NewLease2(gateway, 0, time.Now().Add(1*time.Hour))
	require.NoError(t, err)

	err = lease2.Validate()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrZeroTunnelID)
	assert.False(t, errors.Is(err, ErrZeroGatewayHash))
	assert.False(t, errors.Is(err, ErrExpiredLease))
}

// TestLease2ValidateMultipleErrors verifies Validate() returns all applicable errors.
func TestLease2ValidateMultipleErrors(t *testing.T) {
	lease2, err := NewLease2(data.Hash{}, 0, time.Now().Add(-1*time.Hour))
	require.NoError(t, err)

	err = lease2.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrZeroGatewayHash, "should contain ErrZeroGatewayHash")
	assert.ErrorIs(t, err, ErrZeroTunnelID, "should contain ErrZeroTunnelID")
	assert.ErrorIs(t, err, ErrExpiredLease, "should contain ErrExpiredLease")
}

// TestReadLease2ErrorMessageFormat verifies error messages include expected/actual byte counts.
// Mirrors TestReadLeaseErrorMessageFormat for API consistency.
func TestReadLease2ErrorMessageFormat(t *testing.T) {
	tests := []struct {
		name         string
		inputSize    int
		expectedGot  string
		expectedWant string
	}{
		{"10_bytes", 10, "got 10", "expected 40"},
		{"0_bytes", 0, "got 0", "expected 40"},
		{"39_bytes", 39, "got 39", "expected 40"},
		{"1_byte", 1, "got 1", "expected 40"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shortData := make([]byte, tt.inputSize)
			_, _, err := ReadLease2(shortData)
			require.Error(t, err)
			errMsg := err.Error()
			assert.Contains(t, errMsg, tt.expectedWant,
				"error message should contain expected byte count")
			assert.Contains(t, errMsg, tt.expectedGot,
				"error message should contain actual byte count")
		})
	}
}

// TestLease2ValidateNullDateDistinctFromExpired verifies that end_date=0 returns
// ErrNullDate and NOT ErrExpiredLease, per spec "Date == 0 is undefined or null".
func TestLease2ValidateNullDateDistinctFromExpired(t *testing.T) {
	gateway := createTestHash(t, "l2_null_date_gw_hash____32_bytes")

	// Construct a Lease2 with end_date = 0 directly (epoch time)
	epochTime := time.Unix(0, 0).UTC()
	lease2, err := NewLease2(gateway, 1, epochTime)
	require.NoError(t, err)
	require.NotNil(t, lease2)

	// end_date bytes must be all-zero to confirm the null sentinel was stored
	require.Equal(t, uint32(0), lease2.EndDate(), "epoch-time lease2 should encode end_date=0")

	validationErr := lease2.Validate()
	require.Error(t, validationErr)
	assert.ErrorIs(t, validationErr, ErrNullDate,
		"end_date=0 must produce ErrNullDate, not ErrExpiredLease")
	assert.False(t, errors.Is(validationErr, ErrExpiredLease),
		"end_date=0 must NOT produce ErrExpiredLease; it is null, not merely expired")
}

// TestLease2ValidateNullDateMultipleErrors verifies ErrNullDate combines with other errors.
func TestLease2ValidateNullDateMultipleErrors(t *testing.T) {
	epochTime := time.Unix(0, 0).UTC()
	lease2, err := NewLease2(data.Hash{}, 1, epochTime)
	require.NoError(t, err)

	validationErr := lease2.Validate()
	require.Error(t, validationErr)
	assert.ErrorIs(t, validationErr, ErrZeroGatewayHash)
	assert.ErrorIs(t, validationErr, ErrNullDate)
	assert.False(t, errors.Is(validationErr, ErrExpiredLease))
}

// TestLease2ValidateNullDateSymmetryWithLease verifies Lease and Lease2
// produce the same error (ErrNullDate) for end_date=0.
func TestLease2ValidateNullDateSymmetryWithLease(t *testing.T) {
	gateway := createTestHash(t, "l2_null_symmetry_gw_____32_bytes")
	epochTime := time.Unix(0, 0).UTC()

	lease, err := NewLease(gateway, 1, epochTime)
	require.NoError(t, err)
	lease2, err := NewLease2(gateway, 1, epochTime)
	require.NoError(t, err)

	leaseErr := lease.Validate()
	lease2Err := lease2.Validate()

	assert.ErrorIs(t, leaseErr, ErrNullDate, "Lease should report ErrNullDate")
	assert.ErrorIs(t, lease2Err, ErrNullDate, "Lease2 should report ErrNullDate")
	assert.False(t, errors.Is(leaseErr, ErrExpiredLease), "Lease should not report ErrExpiredLease")
	assert.False(t, errors.Is(lease2Err, ErrExpiredLease), "Lease2 should not report ErrExpiredLease")
}

// TestLease2DateInt_EpochZeroRoundTrip verifies that a zero end_date round-trips and confirms null.
func TestLease2DateInt_EpochZeroRoundTrip(t *testing.T) {
	epochTime := time.Unix(0, 0).UTC()
	gateway := createTestHash(t, "l2_date_epoch_gw_hash___32_bytes")

	lease2, err := NewLease2(gateway, 1, epochTime)
	require.NoError(t, err)

	assert.Equal(t, uint32(0), lease2.EndDate(),
		"EndDate() should return 0 for epoch-zero (null) end_date")

	// Verify via raw bytes
	endDateBytes := lease2[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:]
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(endDateBytes),
		"raw bytes of end_date should be all-zero")
}
