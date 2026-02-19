package lease

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLeaseRoundTrip verifies that a Lease can be created, serialized,
// parsed, and retain all its original values.
func TestLeaseRoundTrip(t *testing.T) {
	gateway := createTestHash(t, "roundtrip_test_gateway_hash_32by")
	tunnelID := uint32(42424)
	expirationTime := time.Now().Add(1 * time.Hour)

	originalLease, err := NewLease(gateway, tunnelID, expirationTime)
	require.NoError(t, err)

	serialized := originalLease.Bytes()
	assert.Equal(t, LEASE_SIZE, len(serialized))

	parsedLease, remainder, err := ReadLease(serialized)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	assert.Equal(t, originalLease.TunnelGateway(), parsedLease.TunnelGateway())
	assert.Equal(t, originalLease.TunnelID(), parsedLease.TunnelID())
	assert.Equal(t, originalLease.Date(), parsedLease.Date())
	assert.Equal(t, originalLease.Time().UnixMilli(), parsedLease.Time().UnixMilli())
	assert.Equal(t, originalLease.Bytes(), parsedLease.Bytes())
}
