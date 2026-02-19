package lease

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLeaseSizeConstants(t *testing.T) {
	assert.Equal(t, 44, LEASE_SIZE, "LEASE_SIZE should be 44 bytes")
	assert.Equal(t, 32, LEASE_TUNNEL_GW_SIZE, "LEASE_TUNNEL_GW_SIZE should be 32 bytes")
	assert.Equal(t, 4, LEASE_TUNNEL_ID_SIZE, "LEASE_TUNNEL_ID_SIZE should be 4 bytes")
}

func TestLease2SizeConstants(t *testing.T) {
	assert.Equal(t, 40, LEASE2_SIZE, "LEASE2_SIZE should be 40 bytes")
	assert.Equal(t, 4, LEASE2_END_DATE_SIZE, "LEASE2_END_DATE_SIZE should be 4 bytes")
	assert.Equal(t, uint64(1<<32-1), LEASE2_MAX_END_DATE, "LEASE2_MAX_END_DATE should be max uint32")
}

func TestLease2VsLeaseSize(t *testing.T) {
	assert.Equal(t, 40, LEASE2_SIZE, "Lease2 should be 40 bytes")
	assert.Equal(t, 44, LEASE_SIZE, "Lease should be 44 bytes")
	assert.Equal(t, 4, LEASE_SIZE-LEASE2_SIZE, "Lease2 should be 4 bytes smaller than Lease")
}

func TestErrorSentinels(t *testing.T) {
	assert.True(t, errors.Is(ErrExpiredLease, ErrExpiredLease))
	assert.True(t, errors.Is(ErrZeroGatewayHash, ErrZeroGatewayHash))
	assert.True(t, errors.Is(ErrTimestampOverflow, ErrTimestampOverflow))
	assert.False(t, errors.Is(ErrExpiredLease, ErrZeroGatewayHash))
}
