package encrypted_leaseset

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEncryptedLeaseSetConstants verifies that package-level constants match the I2P spec.
func TestEncryptedLeaseSetConstants(t *testing.T) {
	assert.Equal(t, uint8(5), ENCRYPTED_LEASESET_TYPE)
	assert.Equal(t, 109, ENCRYPTED_LEASESET_MIN_SIZE)
	assert.Equal(t, uint16(0x0001), ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS)
	assert.Equal(t, uint16(0x0002), ENCRYPTED_LEASESET_FLAG_UNPUBLISHED)
	assert.Equal(t, uint16(0xFFFC), ENCRYPTED_LEASESET_RESERVED_FLAGS_MASK)
}

// TestNoBlindedflag verifies finding #5: FLAG_BLINDED is removed.
// EncryptedLeaseSet is always blinded by definition; no such flag exists.
func TestNoBlindedflag(t *testing.T) {
	// Verify the constant ENCRYPTED_LEASESET_FLAG_BLINDED does not exist
	// by ensuring bits 15-2 are all reserved (mask = 0xFFFC).
	assert.Equal(t, uint16(0xFFFC), ENCRYPTED_LEASESET_RESERVED_FLAGS_MASK,
		"all bits except 0 and 1 should be reserved")

	// Only offline keys (bit 0) and unpublished (bit 1) are valid
	assert.Equal(t, uint16(0x0001), ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS)
	assert.Equal(t, uint16(0x0002), ENCRYPTED_LEASESET_FLAG_UNPUBLISHED)
}
