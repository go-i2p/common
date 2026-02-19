package lease_set2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLeaseSet2MinSizeConstant verifies the minimum size constant
func TestLeaseSet2MinSizeConstant(t *testing.T) {
	// LEASESET2_MIN_SIZE = 499 (header 395 + options 2 + key-header 5 + key 32 + lease-count 1 + sig 64)
	assert.Equal(t, 499, LEASESET2_MIN_SIZE)
}

// TestLeaseSet2HeaderMinSizeConstant verifies the header minimum size
func TestLeaseSet2HeaderMinSizeConstant(t *testing.T) {
	// Destination (387) + published (4) + expires (2) + flags (2) = 395
	assert.Equal(t, 395, LEASESET2_HEADER_MIN_SIZE)
}

// TestLeaseSet2MinDestinationSizeConstant verifies destination minimum size
func TestLeaseSet2MinDestinationSizeConstant(t *testing.T) {
	assert.Equal(t, 387, LEASESET2_MIN_DESTINATION_SIZE)
}

// TestLeaseSet2FieldSizeConstants verifies the field size constants
func TestLeaseSet2FieldSizeConstants(t *testing.T) {
	assert.Equal(t, 4, LEASESET2_PUBLISHED_SIZE)
	assert.Equal(t, 2, LEASESET2_EXPIRES_SIZE)
	assert.Equal(t, 2, LEASESET2_FLAGS_SIZE)
	assert.Equal(t, 2, LEASESET2_ENCRYPTION_KEY_TYPE_SIZE)
	assert.Equal(t, 2, LEASESET2_ENCRYPTION_KEY_LENGTH_SIZE)
}

// TestLeaseSet2MaxLimitsConstants verifies the max limits
func TestLeaseSet2MaxLimitsConstants(t *testing.T) {
	assert.Equal(t, 16, LEASESET2_MAX_LEASES)
	assert.Equal(t, 16, LEASESET2_MAX_ENCRYPTION_KEYS)
}

// TestLeaseSet2FlagConstants verifies flag bit positions
func TestLeaseSet2FlagConstants(t *testing.T) {
	assert.Equal(t, uint16(0x0001), uint16(LEASESET2_FLAG_OFFLINE_KEYS))
	assert.Equal(t, uint16(0x0002), uint16(LEASESET2_FLAG_UNPUBLISHED))
	assert.Equal(t, uint16(0x0004), uint16(LEASESET2_FLAG_BLINDED))
}

// TestLeaseSet2ExpirationConstants verifies expiration-related constants
func TestLeaseSet2ExpirationConstants(t *testing.T) {
	assert.Equal(t, 65535, LEASESET2_MAX_EXPIRES_OFFSET)
	assert.Equal(t, 660, LEASESET2_TYPICAL_MAX_EXPIRES)
	assert.Equal(t, 65535, METALEASESET_MAX_EXPIRES)
}

// TestLeaseSet2DbStoreTypeConstant verifies the DatabaseStore type byte
func TestLeaseSet2DbStoreTypeConstant(t *testing.T) {
	assert.Equal(t, 0x03, LEASESET2_DBSTORE_TYPE)
}
