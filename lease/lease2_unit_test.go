package lease

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewLease2 tests the NewLease2 constructor
func TestNewLease2(t *testing.T) {
	gateway := createTestHash(t, "lease2_test_gateway_hash32_bytes")
	tunnelID := uint32(54321)
	expiration := time.Now().Add(10 * time.Minute)

	lease2, err := NewLease2(gateway, tunnelID, expiration)
	require.NoError(t, err)
	require.NotNil(t, lease2)

	assert.Equal(t, gateway, lease2.TunnelGateway())
	assert.Equal(t, tunnelID, lease2.TunnelID())
}

func TestLease2TunnelGateway(t *testing.T) {
	gateway := createTestHash(t, "lease2_gw_test_hash_____32_bytes")

	lease2, err := NewLease2(gateway, 1, time.Now().Add(10*time.Minute))
	require.NoError(t, err)
	assert.Equal(t, gateway, lease2.TunnelGateway())
}

func TestLease2TunnelID(t *testing.T) {
	gateway := createTestHash(t, "lease2_tid_test_hash____32_bytes")
	tunnelID := uint32(0xCAFEBABE)

	lease2, err := NewLease2(gateway, tunnelID, time.Now().Add(10*time.Minute))
	require.NoError(t, err)
	assert.Equal(t, tunnelID, lease2.TunnelID())
}

// TestLease2EndDate verifies the 4-byte Unix seconds end date.
func TestLease2EndDate(t *testing.T) {
	gateway := createTestHash(t, "lease2_enddate_hash_____32_bytes")
	expiration := time.Now().Add(10 * time.Minute)

	lease2, err := NewLease2(gateway, 1, expiration)
	require.NoError(t, err)
	assert.Equal(t, uint32(expiration.Unix()), lease2.EndDate())
}

// TestLease2Time verifies that Time() converts the 4-byte seconds timestamp.
func TestLease2Time(t *testing.T) {
	gateway := createTestHash(t, "lease2_time_test_hash___32_bytes")
	expiration := time.Now().Add(30 * time.Minute)

	lease2, err := NewLease2(gateway, 1, expiration)
	require.NoError(t, err)

	// Lease2 stores seconds, so precision is limited to seconds
	assert.InDelta(t, expiration.Unix(), lease2.Time().Unix(), 1)
}

// TestLease2Bytes verifies the complete 40-byte serialization.
func TestLease2Bytes(t *testing.T) {
	gateway := createTestHash(t, "lease2_bytes_test_hash__32_bytes")
	tunnelID := uint32(88888)
	expiration := time.Now().Add(10 * time.Minute)

	lease2, err := NewLease2(gateway, tunnelID, expiration)
	require.NoError(t, err)

	bytes := lease2.Bytes()
	assert.Equal(t, LEASE2_SIZE, len(bytes))
	assert.Equal(t, lease2[:], bytes)
}

// TestLease2DateMethod verifies the Date() conversion from seconds to millis.
func TestLease2DateMethod(t *testing.T) {
	gateway := createTestHash(t, "lease2_date_method_hash_32_bytes")
	expiration := time.Now().Add(10 * time.Minute)

	lease2, err := NewLease2(gateway, 1, expiration)
	require.NoError(t, err)

	date := lease2.Date()
	dateTime := date.Time()
	assert.InDelta(t, expiration.Unix(), dateTime.Unix(), 1)
}

// TestNewLease2Validation tests the NewLease2 constructor behavior.
func TestNewLease2Validation(t *testing.T) {
	tests := []struct {
		name        string
		gateway     data.Hash
		tunnelID    uint32
		expiration  time.Time
		expectError bool
		expectValid bool
	}{
		{
			name:        "valid lease2",
			gateway:     createTestHash(t, "valid_l2_gateway_hash___32_bytes"),
			tunnelID:    12345,
			expiration:  time.Now().Add(10 * time.Minute),
			expectError: false,
			expectValid: true,
		},
		{
			name:        "expired lease2 accepted by constructor",
			gateway:     createTestHash(t, "expired_l2_gateway_hash_32_bytes"),
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
			name:        "far future lease2",
			gateway:     createTestHash(t, "far_future_l2_gw_hash___32_bytes"),
			tunnelID:    99999,
			expiration:  time.Now().Add(365 * 24 * time.Hour),
			expectError: false,
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lease2, err := NewLease2(tt.gateway, tt.tunnelID, tt.expiration)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, lease2)
			} else {
				require.NoError(t, err)
				require.NotNil(t, lease2)
				assert.Equal(t, tt.gateway, lease2.TunnelGateway())
				assert.Equal(t, tt.tunnelID, lease2.TunnelID())
				if tt.expectValid {
					assert.NoError(t, lease2.Validate())
				} else {
					assert.Error(t, lease2.Validate())
				}
			}
		})
	}
}

// TestNewLease2WithZeroTunnelID verifies Lease2 with tunnel ID 0 succeeds.
func TestNewLease2WithZeroTunnelID(t *testing.T) {
	gateway := createTestHash(t, "zero_tid_l2_gw_hash_____32_bytes")
	expiration := time.Now().Add(10 * time.Minute)

	lease2, err := NewLease2(gateway, 0, expiration)
	require.NoError(t, err)
	require.NotNil(t, lease2)
	assert.Equal(t, uint32(0), lease2.TunnelID())
}

// TestLease2ReferenceVector verifies byte-for-byte correctness.
func TestLease2ReferenceVector(t *testing.T) {
	var gatewayBytes [32]byte
	for i := range gatewayBytes {
		gatewayBytes[i] = byte(i)
	}
	gateway := data.Hash(gatewayBytes)
	tunnelID := uint32(0xDEADBEEF)
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
	assert.Equal(t, gateway, lease2.TunnelGateway())
	assert.Equal(t, tunnelID, lease2.TunnelID())
	assert.Equal(t, expSec, lease2.EndDate())
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

func BenchmarkLease2Time(b *testing.B) {
	var lease2 Lease2
	binary.BigEndian.PutUint32(lease2[LEASE_TUNNEL_GW_SIZE+LEASE_TUNNEL_ID_SIZE:], 1700000000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lease2.Time()
	}
}
