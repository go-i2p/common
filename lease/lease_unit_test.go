package lease

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTunnelGateway(t *testing.T) {
	assert := assert.New(t)

	expectedTunnelGatewayBytes := []byte("example_32_bytes_hash_to_test_00")

	var lease_bytes []byte
	lease_bytes = append(lease_bytes, expectedTunnelGatewayBytes...)
	lease_bytes = append(lease_bytes, make([]byte, LEASE_SIZE-LEASE_TUNNEL_GW_SIZE)...)
	lease := Lease(lease_bytes)

	tunnelGateway := lease.TunnelGateway()
	assert.ElementsMatch(tunnelGateway.Bytes(), expectedTunnelGatewayBytes)
}

func TestTunnelID(t *testing.T) {
	assert := assert.New(t)

	expectedTunnelIDBytes := []byte{0x21, 0x37, 0x31, 0x33}

	var lease_bytes []byte
	lease_bytes = append(lease_bytes, make([]byte, LEASE_TUNNEL_GW_SIZE)...)
	lease_bytes = append(lease_bytes, expectedTunnelIDBytes...)
	lease_bytes = append(lease_bytes, make([]byte, LEASE_SIZE-LEASE_TUNNEL_ID_SIZE-LEASE_TUNNEL_GW_SIZE)...)
	lease := Lease(lease_bytes)

	tunnelID := lease.TunnelID()
	assert.Equal(tunnelID, uint32(data.Integer(expectedTunnelIDBytes).Int()))
}

func TestDate(t *testing.T) {
	assert := assert.New(t)

	expectedDateBytes := []byte{0x21, 0x37, 0x31, 0x33, 0x16, 0x93, 0x13, 0x28}

	var lease_bytes []byte
	lease_bytes = append(lease_bytes, make([]byte, LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE)...)
	lease_bytes = append(lease_bytes, expectedDateBytes...)
	lease := Lease(lease_bytes)

	date := lease.Date()
	assert.ElementsMatch(date.Bytes(), expectedDateBytes)
}

// TestLeaseTunnelIDHighBit verifies that Lease.TunnelID() correctly returns
// tunnel IDs with the high bit set (values >= 2^31).
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

// TestLeaseTime verifies that Time() returns the correct expiration time.
func TestLeaseTime(t *testing.T) {
	gateway := createTestHash(t, "time_test_gateway_hash__32_bytes")
	tunnelID := uint32(54321)
	expirationTime := time.Now().Add(30 * time.Minute)

	lease, err := NewLease(gateway, tunnelID, expirationTime)
	require.NoError(t, err)

	assert.Equal(t, lease.Date().Time().UnixMilli(), lease.Time().UnixMilli())
	assert.InDelta(t, expirationTime.UnixMilli(), lease.Time().UnixMilli(), 1000)
}

// TestNewLeaseWithZeroTunnelID verifies that creating a lease with tunnel ID 0 succeeds.
func TestNewLeaseWithZeroTunnelID(t *testing.T) {
	gateway := createTestHash(t, "zero_tid_gateway_hash___32_bytes")
	expirationTime := time.Now().Add(10 * time.Minute)

	lease, err := NewLease(gateway, 0, expirationTime)
	require.NoError(t, err)
	require.NotNil(t, lease)
	assert.Equal(t, uint32(0), lease.TunnelID())
}

// TestNewLeaseValidation tests the NewLease constructor behavior
func TestNewLeaseValidation(t *testing.T) {
	tests := []struct {
		name        string
		gateway     data.Hash
		tunnelID    uint32
		expiration  time.Time
		expectError bool
		expectValid bool
	}{
		{
			name:        "valid lease",
			gateway:     createTestHash(t, "valid_gateway_hash_test_000000__"),
			tunnelID:    12345,
			expiration:  time.Now().Add(10 * time.Minute),
			expectError: false,
			expectValid: true,
		},
		{
			name:        "expired lease accepted by constructor",
			gateway:     createTestHash(t, "expired_gateway_hash_test_0000__"),
			tunnelID:    12345,
			expiration:  time.Now().Add(-10 * time.Minute),
			expectError: false,
			expectValid: false,
		},
		{
			name:        "zero gateway hash accepted by constructor",
			gateway:     data.Hash{},
			tunnelID:    12345,
			expiration:  time.Now().Add(10 * time.Minute),
			expectError: false,
			expectValid: false,
		},
		{
			name:        "far future lease",
			gateway:     createTestHash(t, "far_future_gateway_hash_test_0__"),
			tunnelID:    99999,
			expiration:  time.Now().Add(365 * 24 * time.Hour),
			expectError: false,
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lease, err := NewLease(tt.gateway, tt.tunnelID, tt.expiration)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, lease)
			} else {
				require.NoError(t, err)
				require.NotNil(t, lease)
				assert.Equal(t, tt.gateway, lease.TunnelGateway())
				assert.Equal(t, tt.tunnelID, lease.TunnelID())
				if tt.expectValid {
					assert.NoError(t, lease.Validate())
				} else {
					assert.Error(t, lease.Validate())
				}
			}
		})
	}
}

// TestLeaseTimeDateRoundTrip verifies that Lease.Time() correctly decodes
// the 8-byte millisecond timestamp without signed truncation.
func TestLeaseTimeDateRoundTrip(t *testing.T) {
	gateway := createTestHash(t, "time_roundtrip_gw_hash__32_bytes")

	tests := []struct {
		name   string
		millis uint64
	}{
		{"zero", 0},
		{"epoch_plus_1ms", 1},
		{"recent_date", uint64(time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC).UnixMilli())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var lease Lease
			copy(lease[:LEASE_TUNNEL_GW_SIZE], gateway[:])
			binary.BigEndian.PutUint32(lease[LEASE_TUNNEL_GW_SIZE:], 1)
			binary.BigEndian.PutUint64(lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], tt.millis)

			got := lease.Time()
			gotMillis := uint64(got.UnixMilli())
			assert.Equal(t, tt.millis, gotMillis,
				"Time() should correctly decode millis=%d", tt.millis)
		})
	}
}

// TestLeaseTimeBypassesSignedInt verifies the fix: Time() uses unsigned decoding.
func TestLeaseTimeBypassesSignedInt(t *testing.T) {
	gateway := createTestHash(t, "signed_bypass_gw_hash___32_bytes")

	var lease Lease
	copy(lease[:LEASE_TUNNEL_GW_SIZE], gateway[:])
	binary.BigEndian.PutUint32(lease[LEASE_TUNNEL_GW_SIZE:], 1)

	knownMillis := uint64(1750000000000) // ~2025
	binary.BigEndian.PutUint64(lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], knownMillis)

	got := lease.Time()
	assert.Equal(t, int64(knownMillis), got.UnixMilli())
}

// TestLeaseTimestampRangeAndPrecision verifies that Lease's 8-byte millisecond
// timestamps encode and decode correctly with millisecond precision preserved.
func TestLeaseTimestampRangeAndPrecision(t *testing.T) {
	gateway := createTestHash(t, "timestamp_range_test_gw_hash_32b")

	nearFuture := time.Now().Add(24 * time.Hour)
	leaseNear, err := NewLease(gateway, 1, nearFuture)
	require.NoError(t, err)
	assert.InDelta(t, nearFuture.UnixMilli(), leaseNear.Time().UnixMilli(), 1)

	farFuture := time.Now().Add(365 * 24 * time.Hour)
	leaseFar, err := NewLease(gateway, 2, farFuture)
	require.NoError(t, err)
	assert.InDelta(t, farFuture.UnixMilli(), leaseFar.Time().UnixMilli(), 1)

	preciseTime := time.Now().Add(1 * time.Hour).Truncate(time.Millisecond)
	leasePrecise, err := NewLease(gateway, 3, preciseTime)
	require.NoError(t, err)
	assert.Equal(t, preciseTime.UnixMilli(), leasePrecise.Time().UnixMilli(),
		"Millisecond precision should be preserved")
}

// TestLeaseReferenceVector verifies NewLease produces byte-for-byte identical
// output to manually constructed raw bytes.
func TestLeaseReferenceVector(t *testing.T) {
	var gatewayBytes [32]byte
	for i := range gatewayBytes {
		gatewayBytes[i] = byte(i)
	}
	gateway := data.Hash(gatewayBytes)
	tunnelID := uint32(0xDEADBEEF)
	expTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	expMillis := uint64(expTime.UnixMilli())

	var expected [LEASE_SIZE]byte
	copy(expected[:32], gatewayBytes[:])
	binary.BigEndian.PutUint32(expected[32:36], tunnelID)
	binary.BigEndian.PutUint64(expected[36:44], expMillis)

	lease, err := NewLease(gateway, tunnelID, expTime)
	require.NoError(t, err)

	assert.Equal(t, expected[:], lease.Bytes(),
		"NewLease output must match hand-constructed reference vector")
	assert.Equal(t, gateway, lease.TunnelGateway())
	assert.Equal(t, tunnelID, lease.TunnelID())
	assert.Equal(t, expTime.UnixMilli(), lease.Time().UnixMilli())
}

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

func BenchmarkLeaseTime(b *testing.B) {
	var lease Lease
	binary.BigEndian.PutUint64(lease[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], 1700000000000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lease.Time()
	}
}
