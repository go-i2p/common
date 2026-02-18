package lease

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-i2p/common/data"
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

// TestNewLeaseValidation tests the NewLease constructor behavior
func TestNewLeaseValidation(t *testing.T) {
	tests := []struct {
		name        string
		gateway     data.Hash
		tunnelID    uint32
		expiration  time.Time
		expectError bool
		expectValid bool // whether Validate() should pass
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

// TestNewLease2Validation tests the NewLease2 constructor behavior
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
			gateway:     createTestHash(t, "valid_gateway_hash_test_000000__"),
			tunnelID:    12345,
			expiration:  time.Now().Add(10 * time.Minute),
			expectError: false,
			expectValid: true,
		},
		{
			name:        "expired lease2 accepted by constructor",
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
			name:        "far future lease2",
			gateway:     createTestHash(t, "far_future_gateway_hash_test_0__"),
			tunnelID:    99999,
			expiration:  time.Date(2106, 2, 7, 6, 28, 0, 0, time.UTC),
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

// createTestHash creates a test hash from a string (must be 32 bytes)
func createTestHash(t *testing.T, s string) data.Hash {
	t.Helper()
	if len(s) != 32 {
		t.Fatalf("test hash string must be exactly 32 bytes, got %d", len(s))
	}
	hash, err := data.NewHashFromSlice([]byte(s))
	require.NoError(t, err)
	return hash
}
