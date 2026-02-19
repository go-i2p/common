package lease

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReadLease2ValidData verifies that ReadLease2 correctly parses valid data.
func TestReadLease2ValidData(t *testing.T) {
	gateway := createTestHash(t, "l2_valid_read_gw_hash___32_bytes")
	tunnelID := uint32(12345)
	expiration := time.Now().Add(10 * time.Minute)

	original, err := NewLease2(gateway, tunnelID, expiration)
	require.NoError(t, err)

	dataWithExtra := append(original.Bytes(), []byte("extra_data")...)
	parsed, remainder, err := ReadLease2(dataWithExtra)
	require.NoError(t, err)
	assert.True(t, original.Equal(parsed))
	assert.Equal(t, []byte("extra_data"), remainder)
}

// TestNewLease2FromBytesValidData verifies correct parsing from raw bytes.
func TestNewLease2FromBytesValidData(t *testing.T) {
	gateway := createTestHash(t, "l2_frombytes_gw_hash____32_bytes")
	tunnelID := uint32(54321)
	expiration := time.Now().Add(10 * time.Minute)

	original, err := NewLease2(gateway, tunnelID, expiration)
	require.NoError(t, err)

	parsed, remainder, err := NewLease2FromBytes(original.Bytes())
	require.NoError(t, err)
	require.NotNil(t, parsed)
	assert.Empty(t, remainder)
	assert.True(t, original.Equal(*parsed))
}

// TestLease2TimestampRange verifies that the 4-byte second timestamp has correct range.
func TestLease2TimestampRange(t *testing.T) {
	gateway := createTestHash(t, "l2_ts_range_gw_hash_____32_bytes")

	nearFuture := time.Now().Add(1 * time.Hour)
	lease2, err := NewLease2(gateway, 1, nearFuture)
	require.NoError(t, err)
	assert.InDelta(t, nearFuture.Unix(), int64(lease2.EndDate()), 1)
}

// TestLease2RoundTrip verifies full round-trip: create, serialize, parse.
func TestLease2RoundTrip(t *testing.T) {
	gateway := createTestHash(t, "l2_roundtrip_gw_hash____32_bytes")
	tunnelID := uint32(42424)
	expirationTime := time.Now().Add(1 * time.Hour)

	original, err := NewLease2(gateway, tunnelID, expirationTime)
	require.NoError(t, err)

	serialized := original.Bytes()
	assert.Equal(t, LEASE2_SIZE, len(serialized))

	parsed, remainder, err := ReadLease2(serialized)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	assert.Equal(t, original.TunnelGateway(), parsed.TunnelGateway())
	assert.Equal(t, original.TunnelID(), parsed.TunnelID())
	assert.Equal(t, original.EndDate(), parsed.EndDate())
	assert.Equal(t, original.Bytes(), parsed.Bytes())
	assert.True(t, original.Equal(parsed))
}
