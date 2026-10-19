package meta_leaseset

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"

	common "github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestMetaLeaseSet(t *testing.T, flags uint16) *MetaLeaseSet {
	t.Helper()

	dest := createTestDestinationStruct(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	entry := createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 10)
	mls, err := NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 3600, flags, nil,
		common.Mapping{}, []MetaLeaseSetEntry{entry}, nil, priv,
	)
	require.NoError(t, err)
	return &mls
}

// TestMetaLeaseSetValidateRejectsReservedFlagBits covers the LeaseSet2Header
// requirement "Bits 15-3: set to 0 for compatibility with future uses", which
// MetaLeaseSet inherits.
func TestMetaLeaseSetValidateRejectsReservedFlagBits(t *testing.T) {
	mls := newTestMetaLeaseSet(t, 0)
	require.NoError(t, mls.Validate())
	assert.True(t, mls.IsValid())

	// Bit 3 is the first reserved bit.
	mls.flags = META_LEASESET_FLAG_OFFLINE_KEYS | 0x0008
	assert.Error(t, mls.Validate(), "reserved bit 3 set must fail validation")

	mls.flags = 0x8000
	assert.Error(t, mls.Validate(), "reserved bit 15 set must fail validation")
}

// TestNewMetaLeaseSetRejectsReservedFlagBits verifies the constructor enforces
// the same rule outbound.
func TestNewMetaLeaseSetRejectsReservedFlagBits(t *testing.T) {
	dest := createTestDestinationStruct(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	entry := createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 10)
	_, err = NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 3600, 0x0010, nil,
		common.Mapping{}, []MetaLeaseSetEntry{entry}, nil, priv,
	)
	assert.Error(t, err, "constructor must reject reserved flag bit 4")
}

// TestMetaLeaseSetValidateEntryCountMismatch guards against a header count that
// disagrees with the entries actually present.
func TestMetaLeaseSetValidateEntryCountMismatch(t *testing.T) {
	mls := newTestMetaLeaseSet(t, 0)
	mls.numEntries = 3
	assert.Error(t, mls.Validate(), "declared count != len(entries) must fail")
}

// TestMetaLeaseSetValidateOfflineFlagConsistency checks flags bit 0 against the
// presence of an OfflineSignature ("only present if bit 0 is set in the flags").
func TestMetaLeaseSetValidateOfflineFlagConsistency(t *testing.T) {
	mls := newTestMetaLeaseSet(t, 0)
	// Flag bit 0 set but no offline signature present: the structure is
	// self-inconsistent and cannot be located on the wire.
	mls.flags = META_LEASESET_FLAG_OFFLINE_KEYS
	mls.offlineSignature = nil
	assert.Error(t, mls.Validate(), "flag bit 0 set without an offline signature must fail")
}

// TestMetaLeaseSetValidateEntryReservedFlagBits covers MetaLease's own flags
// field: "Bits 23-4: set to 0 for compatibility with future uses".
func TestMetaLeaseSetValidateEntryReservedFlagBits(t *testing.T) {
	mls := newTestMetaLeaseSet(t, 0)
	mls.entries[0].flags[0] = 0x01 // bits 23-16 must be zero
	assert.Error(t, mls.Validate(), "entry reserved flag bits set must fail")
}

// TestReadMetaLeaseSetWarnsOnReservedFlagsNotRejects documents the deliberate
// inbound-lenient policy: a signed record from a future implementation is kept.
func TestReadMetaLeaseSetWarnsOnReservedFlagsNotRejects(t *testing.T) {
	mls := newTestMetaLeaseSet(t, 0)
	mls.flags |= 0x0008

	wire, err := mls.Bytes()
	require.NoError(t, err)

	parsed, _, err := ReadMetaLeaseSet(wire)
	assert.NoError(t, err, "inbound reserved bits must warn, not reject")
	if err == nil {
		assert.Error(t, parsed.Validate(), "but Validate() must reject them")
	}
}
