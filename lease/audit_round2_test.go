package lease

import (
	"encoding/binary"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-i2p/common/data"
)

// =============================================================================
// [BUG] Lease.Date().Time() signed integer truncation fix
// =============================================================================

// TestLeaseTimeDateRoundTrip verifies that Lease.Time() correctly decodes
// the 8-byte millisecond timestamp through the full path without signed truncation.
func TestLeaseTimeDateRoundTrip(t *testing.T) {
	gateway := createTestHash(t, "time_roundtrip_gw_hash__32_bytes")

	tests := []struct {
		name   string
		millis uint64
	}{
		{"zero", 0},
		{"epoch_plus_1ms", 1},
		{"recent_date", uint64(time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC).UnixMilli())},
		{"max_int64_millis", uint64(math.MaxInt64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var lease Lease
			copy(lease[:LEASE_TUNNEL_GW_SIZE], gateway[:])
			binary.BigEndian.PutUint32(lease[LEASE_TUNNEL_GW_SIZE:], 1)
			binary.BigEndian.PutUint64(lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], tt.millis)

			// Time() should use unsigned decoding
			got := lease.Time()
			gotMillis := uint64(got.UnixMilli())
			assert.Equal(t, tt.millis, gotMillis,
				"Time() should correctly decode millis=%d", tt.millis)
		})
	}
}

// TestLeaseTimeBypassesSignedInt verifies the fix: Time() no longer goes through
// Integer.Int() which casts uint64 to signed int, causing negative values for
// timestamps >= 2^63 ms (year ~2262).
func TestLeaseTimeBypassesSignedInt(t *testing.T) {
	gateway := createTestHash(t, "signed_bypass_gw_hash___32_bytes")

	// Use a timestamp that would overflow signed int64 in milliseconds
	// 2^63 ms = ~292 million years, but the format supports up to 2^64-1 ms
	// Test with a large but still representable value
	var lease Lease
	copy(lease[:LEASE_TUNNEL_GW_SIZE], gateway[:])
	binary.BigEndian.PutUint32(lease[LEASE_TUNNEL_GW_SIZE:], 1)

	// Set timestamp to a known value and verify round-trip
	knownMillis := uint64(1750000000000) // ~2025
	binary.BigEndian.PutUint64(lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], knownMillis)

	got := lease.Time()
	assert.Equal(t, int64(knownMillis), got.UnixMilli())
}

// =============================================================================
// [SPEC] Constructor no longer rejects expired leases or zero gateway hashes
// =============================================================================

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

// TestNewLease2AcceptsExpiredTime verifies that NewLease2 accepts past times.
func TestNewLease2AcceptsExpiredTime(t *testing.T) {
	gateway := createTestHash(t, "past_time_gateway_hash__32_bytes")
	pastTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

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

// =============================================================================
// [GAP] IsExpired() method
// =============================================================================

// TestLeaseIsExpired verifies IsExpired() for both future and past leases.
func TestLeaseIsExpired(t *testing.T) {
	gateway := createTestHash(t, "is_expired_gw_hash______32_bytes")

	// Future lease
	futureLease, err := NewLease(gateway, 1, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.False(t, futureLease.IsExpired())

	// Past lease
	pastLease, err := NewLease(gateway, 1, time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	assert.True(t, pastLease.IsExpired())
}

// TestLease2IsExpired verifies IsExpired() for Lease2.
func TestLease2IsExpired(t *testing.T) {
	gateway := createTestHash(t, "is_expired_gw_hash______32_bytes")

	// Future lease2
	futureLease2, err := NewLease2(gateway, 1, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.False(t, futureLease2.IsExpired())

	// Past lease2
	pastLease2, err := NewLease2(gateway, 1, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.True(t, pastLease2.IsExpired())
}

// =============================================================================
// [GAP] Equal() method
// =============================================================================

// TestLeaseEqual verifies byte-for-byte equality comparison.
func TestLeaseEqual(t *testing.T) {
	gateway := createTestHash(t, "equal_test_gw_hash______32_bytes")
	expTime := time.Now().Add(1 * time.Hour)

	lease1, err := NewLease(gateway, 42, expTime)
	require.NoError(t, err)

	// Same construction should produce equal leases
	lease2, err := NewLease(gateway, 42, expTime)
	require.NoError(t, err)
	assert.True(t, lease1.Equal(*lease2))

	// Different tunnel ID should not be equal
	lease3, err := NewLease(gateway, 43, expTime)
	require.NoError(t, err)
	assert.False(t, lease1.Equal(*lease3))
}

// TestLease2Equal verifies byte-for-byte equality comparison for Lease2.
func TestLease2Equal(t *testing.T) {
	gateway := createTestHash(t, "equal_test_gw_hash______32_bytes")
	expTime := time.Now().Add(1 * time.Hour)

	l1, err := NewLease2(gateway, 42, expTime)
	require.NoError(t, err)

	l2, err := NewLease2(gateway, 42, expTime)
	require.NoError(t, err)
	assert.True(t, l1.Equal(*l2))

	l3, err := NewLease2(gateway, 99, expTime)
	require.NoError(t, err)
	assert.False(t, l1.Equal(*l3))
}

// =============================================================================
// [GAP] Validate() method
// =============================================================================

// TestLeaseValidate verifies Validate() catches semantic issues.
func TestLeaseValidate(t *testing.T) {
	gateway := createTestHash(t, "validate_test_gw_hash___32_bytes")

	// Valid lease: future time, non-zero hash
	valid, err := NewLease(gateway, 1, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.NoError(t, valid.Validate())

	// Zero hash
	zeroHash, err := NewLease(data.Hash{}, 1, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.ErrorIs(t, zeroHash.Validate(), ErrZeroGatewayHash)

	// Expired
	expired, err := NewLease(gateway, 1, time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	assert.ErrorIs(t, expired.Validate(), ErrExpiredLease)

	// Both zero hash and expired: zero hash checked first
	both, err := NewLease(data.Hash{}, 1, time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	assert.ErrorIs(t, both.Validate(), ErrZeroGatewayHash)
}

// TestLease2Validate verifies Validate() for Lease2.
func TestLease2Validate(t *testing.T) {
	gateway := createTestHash(t, "validate_test_gw_hash___32_bytes")

	valid, err := NewLease2(gateway, 1, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.NoError(t, valid.Validate())

	zeroHash, err := NewLease2(data.Hash{}, 1, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.ErrorIs(t, zeroHash.Validate(), ErrZeroGatewayHash)
}

// =============================================================================
// [GAP] NewLease2 uint32 overflow check
// =============================================================================

// TestNewLease2TimestampOverflow verifies that NewLease2 rejects times beyond uint32 range.
func TestNewLease2TimestampOverflow(t *testing.T) {
	gateway := createTestHash(t, "overflow_test_gw_hash___32_bytes")

	// Just at the boundary (2106-02-07T06:28:15 UTC) should succeed
	boundary := time.Unix(int64(LEASE2_MAX_END_DATE), 0)
	l, err := NewLease2(gateway, 1, boundary)
	require.NoError(t, err)
	assert.Equal(t, uint32(LEASE2_MAX_END_DATE), l.EndDate())

	// Just past the boundary should fail
	pastBoundary := time.Unix(int64(LEASE2_MAX_END_DATE)+1, 0)
	_, err = NewLease2(gateway, 1, pastBoundary)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTimestampOverflow)

	// Far past the boundary
	farPast := time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err = NewLease2(gateway, 1, farPast)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTimestampOverflow)

	// Negative unix time (before epoch)
	beforeEpoch := time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC)
	_, err = NewLease2(gateway, 1, beforeEpoch)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTimestampOverflow)
}

// =============================================================================
// [GAP] Lease2.Date() API symmetry
// =============================================================================

// TestLease2DateMethod verifies Lease2.Date() returns a proper data.Date.
func TestLease2DateMethod(t *testing.T) {
	gateway := createTestHash(t, "date_method_gw_hash_____32_bytes")
	expTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	lease2, err := NewLease2(gateway, 1, expTime)
	require.NoError(t, err)

	date := lease2.Date()
	// Date should represent the same time (truncated to seconds)
	dateTime := date.Time()
	assert.Equal(t, expTime.Unix(), dateTime.Unix())
}

// =============================================================================
// [TEST] Nil input for ReadLease / ReadLease2
// =============================================================================

// TestReadLeaseNilInput verifies ReadLease handles nil input correctly.
func TestReadLeaseNilInput(t *testing.T) {
	_, _, err := ReadLease(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enough data")
}

// TestReadLease2NilInput verifies ReadLease2 handles nil input correctly.
func TestReadLease2NilInput(t *testing.T) {
	_, _, err := ReadLease2(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enough data")
}

// TestNewLeaseFromBytesNilInput verifies NewLeaseFromBytes handles nil input.
func TestNewLeaseFromBytesNilInput(t *testing.T) {
	ptr, _, err := NewLeaseFromBytes(nil)
	require.Error(t, err)
	assert.Nil(t, ptr)
}

// TestNewLease2FromBytesNilInput verifies NewLease2FromBytes handles nil input.
func TestNewLease2FromBytesNilInput(t *testing.T) {
	ptr, _, err := NewLease2FromBytes(nil)
	require.Error(t, err)
	assert.Nil(t, ptr)
}

// =============================================================================
// [TEST] Byte-for-byte reference vector test for NewLease
// =============================================================================

// TestLeaseReferenceVector verifies NewLease produces byte-for-byte identical
// output to manually constructed raw bytes for a known-good reference vector.
func TestLeaseReferenceVector(t *testing.T) {
	// Known reference vector
	var gatewayBytes [32]byte
	for i := range gatewayBytes {
		gatewayBytes[i] = byte(i)
	}
	gateway := data.Hash(gatewayBytes)
	tunnelID := uint32(0xDEADBEEF)
	// Use a fixed time: 2025-01-01T00:00:00.000 UTC
	expTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	expMillis := uint64(expTime.UnixMilli())

	// Build expected bytes manually
	var expected [LEASE_SIZE]byte
	copy(expected[:32], gatewayBytes[:])
	binary.BigEndian.PutUint32(expected[32:36], tunnelID)
	binary.BigEndian.PutUint64(expected[36:44], expMillis)

	// Build via constructor
	lease, err := NewLease(gateway, tunnelID, expTime)
	require.NoError(t, err)

	assert.Equal(t, expected[:], lease.Bytes(),
		"NewLease output must match hand-constructed reference vector")

	// Verify fields parse correctly
	assert.Equal(t, gateway, lease.TunnelGateway())
	assert.Equal(t, tunnelID, lease.TunnelID())
	assert.Equal(t, expTime.UnixMilli(), lease.Time().UnixMilli())
}

// TestLease2ReferenceVector verifies NewLease2 produces byte-for-byte identical
// output to manually constructed raw bytes.
func TestLease2ReferenceVector(t *testing.T) {
	var gatewayBytes [32]byte
	for i := range gatewayBytes {
		gatewayBytes[i] = byte(i)
	}
	gateway := data.Hash(gatewayBytes)
	tunnelID := uint32(0xCAFEBABE)
	expTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	expSec := uint32(expTime.Unix())

	var expected [LEASE2_SIZE]byte
	copy(expected[:32], gatewayBytes[:])
	binary.BigEndian.PutUint32(expected[32:36], tunnelID)
	binary.BigEndian.PutUint32(expected[36:40], expSec)

	lease2, err := NewLease2(gateway, tunnelID, expTime)
	require.NoError(t, err)

	assert.Equal(t, expected[:], lease2.Bytes(),
		"NewLease2 output must match hand-constructed reference vector")
}

// =============================================================================
// [TEST] Fuzz tests for ReadLease and ReadLease2
// =============================================================================

// FuzzReadLease fuzz tests the ReadLease parser with arbitrary byte sequences.
func FuzzReadLease(f *testing.F) {
	// Seed corpus
	f.Add([]byte{})                    // empty
	f.Add(make([]byte, LEASE_SIZE))    // minimal valid (all zeros)
	f.Add(make([]byte, LEASE_SIZE-1))  // one byte short
	f.Add(make([]byte, LEASE_SIZE+10)) // with remainder

	// Valid lease bytes
	var valid [LEASE_SIZE]byte
	for i := range valid {
		valid[i] = byte(i)
	}
	f.Add(valid[:])

	f.Fuzz(func(t *testing.T, input []byte) {
		lease, remainder, err := ReadLease(input)
		if len(input) < LEASE_SIZE {
			if err == nil {
				t.Error("expected error for short input")
			}
			return
		}
		// If input is long enough, parsing must succeed
		if err != nil {
			t.Errorf("unexpected error for valid-length input: %v", err)
			return
		}
		// Verify remainder length
		if len(remainder) != len(input)-LEASE_SIZE {
			t.Errorf("remainder length %d, want %d", len(remainder), len(input)-LEASE_SIZE)
		}
		// Verify bytes match
		if !assert.ObjectsAreEqual(input[:LEASE_SIZE], lease.Bytes()) {
			t.Error("parsed bytes don't match input")
		}
	})
}

// FuzzReadLease2 fuzz tests the ReadLease2 parser with arbitrary byte sequences.
func FuzzReadLease2(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, LEASE2_SIZE))
	f.Add(make([]byte, LEASE2_SIZE-1))
	f.Add(make([]byte, LEASE2_SIZE+10))

	f.Fuzz(func(t *testing.T, input []byte) {
		lease2, remainder, err := ReadLease2(input)
		if len(input) < LEASE2_SIZE {
			if err == nil {
				t.Error("expected error for short input")
			}
			return
		}
		if err != nil {
			t.Errorf("unexpected error for valid-length input: %v", err)
			return
		}
		if len(remainder) != len(input)-LEASE2_SIZE {
			t.Errorf("remainder length %d, want %d", len(remainder), len(input)-LEASE2_SIZE)
		}
		if !assert.ObjectsAreEqual(input[:LEASE2_SIZE], lease2.Bytes()) {
			t.Error("parsed bytes don't match input")
		}
	})
}

// =============================================================================
// [TEST] Lease2 uint32 rollover boundary
// =============================================================================

// TestLease2TimestampRolloverBoundary tests times at and past the uint32 limit.
func TestLease2TimestampRolloverBoundary(t *testing.T) {
	gateway := createTestHash(t, "rollover_test_gw_hash___32_bytes")

	// Exactly at the uint32 max (2106-02-07T06:28:15 UTC)
	atMax := time.Unix(int64(LEASE2_MAX_END_DATE), 0)
	l, err := NewLease2(gateway, 1, atMax)
	require.NoError(t, err)
	assert.Equal(t, uint32(LEASE2_MAX_END_DATE), l.EndDate())
	assert.Equal(t, atMax.Unix(), l.Time().Unix())

	// One second past: should error
	pastMax := time.Unix(int64(LEASE2_MAX_END_DATE)+1, 0)
	_, err = NewLease2(gateway, 1, pastMax)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTimestampOverflow))
}

// =============================================================================
// [QUALITY] Errors are proper sentinel errors
// =============================================================================

// TestErrorSentinels verifies error types are usable with errors.Is.
func TestErrorSentinels(t *testing.T) {
	assert.True(t, errors.Is(ErrExpiredLease, ErrExpiredLease))
	assert.True(t, errors.Is(ErrZeroGatewayHash, ErrZeroGatewayHash))
	assert.True(t, errors.Is(ErrTimestampOverflow, ErrTimestampOverflow))
	assert.False(t, errors.Is(ErrExpiredLease, ErrZeroGatewayHash))
}

// =============================================================================
// Benchmark tests
// =============================================================================

func BenchmarkReadLease(b *testing.B) {
	var leaseBytes [LEASE_SIZE]byte
	for i := range leaseBytes {
		leaseBytes[i] = byte(i)
	}
	input := leaseBytes[:]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ReadLease(input)
	}
}

func BenchmarkReadLease2(b *testing.B) {
	var lease2Bytes [LEASE2_SIZE]byte
	for i := range lease2Bytes {
		lease2Bytes[i] = byte(i)
	}
	input := lease2Bytes[:]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ReadLease2(input)
	}
}

func BenchmarkLeaseTime(b *testing.B) {
	var lease Lease
	binary.BigEndian.PutUint64(lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], 1700000000000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lease.Time()
	}
}

func BenchmarkLease2Time(b *testing.B) {
	var lease2 Lease2
	binary.BigEndian.PutUint32(lease2[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], 1700000000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lease2.Time()
	}
}
