package lease_set

import (
	"testing"

	"github.com/go-i2p/common/lease"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- NewLeaseSet rejects too many leases ---

func TestValidation_TooManyLeases(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	_, err = createTestLeaseSet(t, routerInfo, 17)
	require.Error(t, err)
	assert.Equal(t, "invalid lease set: more than 16 leases", err.Error())
}

// --- Validate detects zero leases (should succeed per spec) ---

func TestValidation_ValidateZeroLeases(t *testing.T) {
	dest, encKey, sigKey, sigPrivKey, err := generateTestDestination(t)
	require.NoError(t, err)

	leaseSet, err := NewLeaseSet(*dest, encKey, sigKey, []lease.Lease{}, sigPrivKey)
	require.NoError(t, err)

	err = leaseSet.Validate()
	assert.NoError(t, err, "zero leases should be valid per spec")
}

// --- Validate detects max leases ---

func TestValidation_ValidateMaxLeases(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 16)
	require.NoError(t, err)

	err = leaseSet.Validate()
	assert.NoError(t, err, "16 leases (max) should be valid")
}

// --- ReadLeaseSet with malformed input ---

func TestValidation_ReadLeaseSetMalformedInput(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		_, err := ReadLeaseSet(nil)
		assert.Error(t, err)
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := ReadLeaseSet([]byte{})
		assert.Error(t, err)
	})

	t.Run("short input", func(t *testing.T) {
		_, err := ReadLeaseSet(make([]byte, 100))
		assert.Error(t, err)
	})

	t.Run("exact minimum size", func(t *testing.T) {
		_, err := ReadLeaseSet(make([]byte, 387))
		assert.Error(t, err)
	})
}

// --- ReadLeaseSet with excessive lease count ---

func TestValidation_ReadLeaseSetExcessiveLeaseCount(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	dest := leaseSet.Destination()
	destBytes, _ := dest.KeysAndCert.Bytes()
	sigKey, _ := leaseSet.SigningKey()
	leaseCountOffset := len(destBytes) + LEASE_SET_PUBKEY_SIZE + len(sigKey.Bytes())

	if leaseCountOffset < len(lsBytes) {
		tampered := make([]byte, len(lsBytes))
		copy(tampered, lsBytes)
		tampered[leaseCountOffset] = 17

		_, err = ReadLeaseSet(tampered)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid lease count")
	}
}

// --- ReadLeaseSet does not verify signature ---

func TestValidation_ReadLeaseSetNoVerify(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	// Tamper with a byte in the encryption key area
	if len(lsBytes) > 400 {
		lsBytes[400] ^= 0xFF
	}

	// ReadLeaseSet should succeed (no verification during parsing)
	_, err = ReadLeaseSet(lsBytes)
	assert.NoError(t, err, "ReadLeaseSet should not verify signature during parsing")
}

// --- ParseSignature error handling ---

func TestValidation_ParseSignatureErrorHandling(t *testing.T) {
	// parseSignature needs a destination.Destination with a valid certificate
	// to determine signature size. With a zero-value dest and short data,
	// it should return an error.
	dest, _, _, _, err := generateTestDestination(t)
	require.NoError(t, err)

	shortData := make([]byte, 5)
	_, _, err = parseSignature(shortData, *dest)
	assert.Error(t, err)
}

// --- ParseSignature trailing data ---

func TestValidation_ParseSignatureTrailingData(t *testing.T) {
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	require.NoError(t, err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	require.NoError(t, err)

	lsBytes, err := leaseSet.Bytes()
	require.NoError(t, err)

	// Add trailing data
	withTrailing := append(lsBytes, []byte{0xDE, 0xAD, 0xBE, 0xEF}...)

	// ReadLeaseSet should still succeed (trailing data warning only)
	parsed, err := ReadLeaseSet(withTrailing)
	assert.NoError(t, err)
	assert.NotNil(t, parsed)
}
