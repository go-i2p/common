package lease

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReadLeaseInsufficientData verifies error on short input.
func TestReadLeaseInsufficientData(t *testing.T) {
	shortData := make([]byte, LEASE_SIZE-1)
	_, _, err := ReadLease(shortData)
	assert.Error(t, err)
}

// TestReadLeaseExactSize verifies correct parsing with exact-size input.
func TestReadLeaseExactSize(t *testing.T) {
	gateway := createTestHash(t, "exact_size_gw_hash______32_bytes")
	lease, err := NewLease(gateway, 1, time.Now().Add(10*time.Minute))
	require.NoError(t, err)

	parsed, remainder, err := ReadLease(lease.Bytes())
	require.NoError(t, err)
	assert.Empty(t, remainder)
	assert.True(t, lease.Equal(parsed))
}

// TestReadLeaseNilInput verifies error on nil input.
func TestReadLeaseNilInput(t *testing.T) {
	_, _, err := ReadLease(nil)
	assert.Error(t, err)
}

// TestNewLeaseFromBytesValidData verifies correct parsing from raw bytes.
func TestNewLeaseFromBytesValidData(t *testing.T) {
	gateway := createTestHash(t, "frombytes_gw_hash_______32_bytes")
	tunnelID := uint32(54321)
	expiration := time.Now().Add(10 * time.Minute)

	original, err := NewLease(gateway, tunnelID, expiration)
	require.NoError(t, err)

	parsed, remainder, err := NewLeaseFromBytes(original.Bytes())
	require.NoError(t, err)
	require.NotNil(t, parsed)
	assert.Empty(t, remainder)
	assert.True(t, original.Equal(*parsed))
}

// TestNewLeaseFromBytesInsufficientData verifies error on short input.
func TestNewLeaseFromBytesInsufficientData(t *testing.T) {
	shortData := make([]byte, LEASE_SIZE-1)
	_, _, err := NewLeaseFromBytes(shortData)
	assert.Error(t, err)
}

// TestNewLeaseFromBytesWithRemainder verifies remainder is returned correctly.
func TestNewLeaseFromBytesWithRemainder(t *testing.T) {
	gateway := createTestHash(t, "remainder_gw_hash_______32_bytes")
	tunnelID := uint32(99999)
	expiration := time.Now().Add(10 * time.Minute)

	original, err := NewLease(gateway, tunnelID, expiration)
	require.NoError(t, err)

	dataWithExtra := append(original.Bytes(), []byte("extra")...)
	parsed, remainder, err := NewLeaseFromBytes(dataWithExtra)
	require.NoError(t, err)
	require.NotNil(t, parsed)
	assert.Equal(t, []byte("extra"), remainder)
	assert.True(t, original.Equal(*parsed))
}

// TestNewLeaseFromBytesNilInput verifies error on nil input.
func TestNewLeaseFromBytesNilInput(t *testing.T) {
	_, _, err := NewLeaseFromBytes(nil)
	assert.Error(t, err)
}
