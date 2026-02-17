package lease

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Finding 1+12: TunnelID correctness on high-bit values ---

// TestLeaseTunnelIDHighBit verifies that Lease.TunnelID() correctly returns
// tunnel IDs with the high bit set (values >= 2^31), which would be incorrect
// on 32-bit platforms with the old data.Integer.Int() path.
func TestLeaseTunnelIDHighBit(t *testing.T) {
	testCases := []struct {
		name     string
		tunnelID uint32
	}{
		{"max_uint32", 0xFFFFFFFF},
		{"high_bit_set", 0x80000000},
		{"just_over_int31", 0x80000001},
		{"typical_high", 0xDEADBEEF},
		{"normal_value", 12345},
		{"zero", 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var leaseBytes [LEASE_SIZE]byte
			binary.BigEndian.PutUint32(leaseBytes[LEASE_TUNNEL_GW_SIZE:], tc.tunnelID)
			lease := Lease(leaseBytes)
			assert.Equal(t, tc.tunnelID, lease.TunnelID(),
				"TunnelID should correctly decode %d (0x%X)", tc.tunnelID, tc.tunnelID)
		})
	}
}

// --- Finding 4: Lease.Bytes() ---

// TestLeaseBytes verifies that Bytes() returns the complete 44-byte Lease structure.
func TestLeaseBytes(t *testing.T) {
	gateway := createTestHash(t, "bytes_test_gateway_hash_32_bytes")
	tunnelID := uint32(77777)
	expirationTime := time.Now().Add(10 * time.Minute)

	lease, err := NewLease(gateway, tunnelID, expirationTime)
	require.NoError(t, err)

	bytes := lease.Bytes()
	assert.Equal(t, LEASE_SIZE, len(bytes))
	assert.Equal(t, lease[:], bytes)
}

// --- Finding 5: Lease.Time() ---

// TestLeaseTime verifies that Time() returns the correct expiration time
// matching what Date().Time() would return.
func TestLeaseTime(t *testing.T) {
	gateway := createTestHash(t, "time_test_gateway_hash__32_bytes")
	tunnelID := uint32(54321)
	expirationTime := time.Now().Add(30 * time.Minute)

	lease, err := NewLease(gateway, tunnelID, expirationTime)
	require.NoError(t, err)

	// Time() should match Date().Time()
	assert.Equal(t, lease.Date().Time(), lease.Time())
	// Millisecond precision: within 1 second of target
	assert.InDelta(t, expirationTime.UnixMilli(), lease.Time().UnixMilli(), 1000)
}

// --- Finding 6: Tunnel ID 0 warning ---

// TestNewLeaseWithZeroTunnelID verifies that creating a lease with tunnel ID 0
// succeeds (it is not an error) but the tunnel ID is stored correctly.
func TestNewLeaseWithZeroTunnelID(t *testing.T) {
	gateway := createTestHash(t, "zero_tid_gateway_hash___32_bytes")
	expirationTime := time.Now().Add(10 * time.Minute)

	// Tunnel ID 0 should not return an error (it's a soft recommendation)
	lease, err := NewLease(gateway, 0, expirationTime)
	require.NoError(t, err)
	require.NotNil(t, lease)
	assert.Equal(t, uint32(0), lease.TunnelID())
}

// TestNewLease2WithZeroTunnelID verifies the same for Lease2.
func TestNewLease2WithZeroTunnelID(t *testing.T) {
	gateway := createTestHash(t, "zero_tid_gateway_hash___32_bytes")
	expirationTime := time.Now().Add(10 * time.Minute)

	lease2, err := NewLease2(gateway, 0, expirationTime)
	require.NoError(t, err)
	require.NotNil(t, lease2)
	assert.Equal(t, uint32(0), lease2.TunnelID())
}

// --- Finding 7: ReadLease insufficient data ---

// TestReadLeaseInsufficientData verifies that ReadLease returns an error
// when the input data is shorter than 44 bytes.
func TestReadLeaseInsufficientData(t *testing.T) {
	testCases := []int{0, 1, 10, 20, 30, 43}

	for _, dataLen := range testCases {
		insufficientData := make([]byte, dataLen)
		_, _, err := ReadLease(insufficientData)
		assert.Error(t, err, "Expected error for data length %d", dataLen)
		assert.Contains(t, err.Error(), "not enough data")
		assert.Contains(t, err.Error(), "expected")
		assert.Contains(t, err.Error(), "got")
	}
}

// --- Finding 8: ReadLease exact-size ---

// TestReadLeaseExactSize verifies that ReadLease correctly handles
// data that is exactly 44 bytes with no remainder.
func TestReadLeaseExactSize(t *testing.T) {
	gateway := createTestHash(t, "exact_size_gateway_hash_32_bytes")
	tunnelID := uint32(99999)
	expirationTime := time.Now().Add(1 * time.Hour)

	lease, err := NewLease(gateway, tunnelID, expirationTime)
	require.NoError(t, err)

	// Parse exactly 44 bytes
	parsedLease, remainder, err := ReadLease(lease.Bytes())
	require.NoError(t, err)
	assert.Empty(t, remainder)
	assert.Equal(t, lease.Bytes(), parsedLease.Bytes())
}

// --- Finding 9: NewLeaseFromBytes tests ---

// TestNewLeaseFromBytesValidData verifies that NewLeaseFromBytes correctly
// creates a Lease pointer from valid byte data.
func TestNewLeaseFromBytesValidData(t *testing.T) {
	gateway := createTestHash(t, "frombytes_test_gw_hash__32_bytes")
	tunnelID := uint32(11111)
	expirationTime := time.Now().Add(20 * time.Minute)

	originalLease, err := NewLease(gateway, tunnelID, expirationTime)
	require.NoError(t, err)

	// Parse using pointer function
	leasePtr, remainder, err := NewLeaseFromBytes(originalLease.Bytes())
	require.NoError(t, err)
	require.NotNil(t, leasePtr)
	assert.Empty(t, remainder)

	// Verify pointer data matches original
	assert.Equal(t, originalLease.TunnelGateway(), leasePtr.TunnelGateway())
	assert.Equal(t, originalLease.TunnelID(), leasePtr.TunnelID())
	assert.Equal(t, originalLease.Date(), leasePtr.Date())
}

// TestNewLeaseFromBytesInsufficientData verifies that NewLeaseFromBytes
// returns nil and an error when given insufficient data.
func TestNewLeaseFromBytesInsufficientData(t *testing.T) {
	insufficientData := make([]byte, 20)
	leasePtr, _, err := NewLeaseFromBytes(insufficientData)
	assert.Error(t, err)
	assert.Nil(t, leasePtr)
}

// TestNewLeaseFromBytesWithRemainder verifies remainder handling.
func TestNewLeaseFromBytesWithRemainder(t *testing.T) {
	gateway := createTestHash(t, "remainder_test_gw_hash__32_bytes")
	tunnelID := uint32(22222)
	expirationTime := time.Now().Add(15 * time.Minute)

	originalLease, err := NewLease(gateway, tunnelID, expirationTime)
	require.NoError(t, err)

	extraData := []byte("extra_trailing_data")
	testData := append(originalLease.Bytes(), extraData...)

	leasePtr, remainder, err := NewLeaseFromBytes(testData)
	require.NoError(t, err)
	require.NotNil(t, leasePtr)
	assert.Equal(t, extraData, remainder)
	assert.Equal(t, originalLease.TunnelGateway(), leasePtr.TunnelGateway())
}

// --- Finding 10: Round-trip test for Lease ---

// TestLeaseRoundTrip verifies that a Lease can be created, serialized,
// parsed, and retain all its original values.
func TestLeaseRoundTrip(t *testing.T) {
	gateway := createTestHash(t, "roundtrip_test_gateway_hash_32by")
	tunnelID := uint32(42424)
	expirationTime := time.Now().Add(1 * time.Hour)

	// Create original Lease
	originalLease, err := NewLease(gateway, tunnelID, expirationTime)
	require.NoError(t, err)

	// Serialize to bytes
	serialized := originalLease.Bytes()
	assert.Equal(t, LEASE_SIZE, len(serialized))

	// Parse back from bytes
	parsedLease, remainder, err := ReadLease(serialized)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	// Verify all fields match
	assert.Equal(t, originalLease.TunnelGateway(), parsedLease.TunnelGateway())
	assert.Equal(t, originalLease.TunnelID(), parsedLease.TunnelID())
	assert.Equal(t, originalLease.Date(), parsedLease.Date())
	assert.Equal(t, originalLease.Time().UnixMilli(), parsedLease.Time().UnixMilli())
	assert.Equal(t, originalLease.Bytes(), parsedLease.Bytes())
}

// --- Finding 11: Timestamp range and precision test for Lease ---

// TestLeaseTimestampRangeAndPrecision verifies that Lease's 8-byte millisecond
// timestamps encode and decode correctly, and that millisecond precision is preserved.
func TestLeaseTimestampRangeAndPrecision(t *testing.T) {
	gateway := createTestHash(t, "timestamp_range_test_gw_hash_32b")

	// Test near-future timestamp
	nearFuture := time.Now().Add(24 * time.Hour)
	leaseNear, err := NewLease(gateway, 1, nearFuture)
	require.NoError(t, err)
	// Millisecond precision should be preserved (within 1ms)
	assert.InDelta(t, nearFuture.UnixMilli(), leaseNear.Time().UnixMilli(), 1)

	// Test far-future timestamp
	farFuture := time.Now().Add(365 * 24 * time.Hour)
	leaseFar, err := NewLease(gateway, 2, farFuture)
	require.NoError(t, err)
	assert.InDelta(t, farFuture.UnixMilli(), leaseFar.Time().UnixMilli(), 1)

	// Test that millisecond precision is preserved (not truncated to seconds)
	// Use a time with non-zero milliseconds
	preciseTime := time.Now().Add(1 * time.Hour).Truncate(time.Millisecond)
	leasePrecise, err := NewLease(gateway, 3, preciseTime)
	require.NoError(t, err)
	assert.Equal(t, preciseTime.UnixMilli(), leasePrecise.Time().UnixMilli(),
		"Millisecond precision should be preserved")
}

// --- Finding 13+14: Error message format ---

// TestReadLeaseErrorMessageFormat verifies that ReadLease error messages
// include expected and actual byte counts, matching ReadLease2 format.
func TestReadLeaseErrorMessageFormat(t *testing.T) {
	shortData := make([]byte, 10)
	_, _, err := ReadLease(shortData)
	require.Error(t, err)
	errMsg := err.Error()
	assert.Contains(t, errMsg, "expected 44")
	assert.Contains(t, errMsg, "got 10")
}
