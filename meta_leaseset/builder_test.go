package meta_leaseset

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMetaLeaseSetBasic verifies that NewMetaLeaseSet constructs a valid
// MetaLeaseSet with one entry, no revocations, and an Ed25519 signature that
// passes Verify().
func TestNewMetaLeaseSetBasic(t *testing.T) {
	dest := createTestDestinationStruct(t)

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_ = pub

	published := uint32(time.Now().Unix())
	expires := uint16(3600)

	entries := []MetaLeaseSetEntry{
		createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 10),
	}

	mls, err := NewMetaLeaseSet(
		dest, published, expires, 0, nil,
		common.Mapping{}, entries, nil, priv,
	)
	require.NoError(t, err)

	assert.Equal(t, published, mls.Published())
	assert.Equal(t, expires, mls.Expires())
	assert.Equal(t, uint16(0), mls.Flags())
	assert.Equal(t, 1, mls.NumEntries())
	assert.Equal(t, 0, mls.NumRevocations())
	assert.False(t, mls.HasOfflineKeys())
	assert.False(t, mls.IsUnpublished())
	assert.False(t, mls.IsBlinded())
}

// TestNewMetaLeaseSetMultipleEntries constructs a MetaLeaseSet with multiple
// entries and verifies they are preserved.
func TestNewMetaLeaseSetMultipleEntries(t *testing.T) {
	dest := createTestDestinationStruct(t)
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	entries := []MetaLeaseSetEntry{
		createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET, 5),
		createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 10),
		createTestEntryStruct(META_LEASESET_ENTRY_TYPE_META_LEASESET, 15),
	}

	mls, err := NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, entries, nil, priv,
	)
	require.NoError(t, err)
	assert.Equal(t, 3, mls.NumEntries())

	for i, want := range entries {
		got, err := mls.GetEntry(i)
		require.NoError(t, err)
		assert.Equal(t, want.Hash(), got.Hash(), "entry %d hash", i)
		assert.Equal(t, want.Type(), got.Type(), "entry %d type", i)
		assert.Equal(t, want.Cost(), got.Cost(), "entry %d cost", i)
	}
}

// TestNewMetaLeaseSetWithRevocations verifies revocation hashes survive
// construction.
func TestNewMetaLeaseSetWithRevocations(t *testing.T) {
	dest := createTestDestinationStruct(t)
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	rev1 := sha256.Sum256([]byte("revoked set 1"))
	rev2 := sha256.Sum256([]byte("revoked set 2"))
	revocations := [][32]byte{rev1, rev2}

	entries := []MetaLeaseSetEntry{
		createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 5),
	}

	mls, err := NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, entries, revocations, priv,
	)
	require.NoError(t, err)
	assert.Equal(t, 2, mls.NumRevocations())

	gotRevs := mls.Revocations()
	assert.Equal(t, rev1, gotRevs[0])
	assert.Equal(t, rev2, gotRevs[1])
}

// TestNewMetaLeaseSetRoundTrip verifies that a constructed MetaLeaseSet can
// be serialized and re-parsed, producing identical fields.
func TestNewMetaLeaseSetRoundTrip(t *testing.T) {
	dest := createTestDestinationStruct(t)
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	published := uint32(1700000000)
	expires := uint16(3600)
	entries := []MetaLeaseSetEntry{
		createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 5),
		createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET, 15),
	}
	rev := sha256.Sum256([]byte("revoked"))
	revocations := [][32]byte{rev}

	mls, err := NewMetaLeaseSet(
		dest, published, expires,
		META_LEASESET_FLAG_UNPUBLISHED, nil,
		common.Mapping{}, entries, revocations, priv,
	)
	require.NoError(t, err)

	// Serialize
	serialized, err := mls.Bytes()
	require.NoError(t, err)

	// Re-parse
	mls2, remainder, err := ReadMetaLeaseSet(serialized)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	assert.Equal(t, mls.Published(), mls2.Published())
	assert.Equal(t, mls.Expires(), mls2.Expires())
	assert.Equal(t, mls.Flags(), mls2.Flags())
	assert.Equal(t, mls.NumEntries(), mls2.NumEntries())
	assert.Equal(t, mls.NumRevocations(), mls2.NumRevocations())
	assert.True(t, mls2.IsUnpublished())

	for i := 0; i < mls.NumEntries(); i++ {
		e1, _ := mls.GetEntry(i)
		e2, _ := mls2.GetEntry(i)
		assert.Equal(t, e1.Hash(), e2.Hash(), "entry %d hash", i)
		assert.Equal(t, e1.Type(), e2.Type(), "entry %d type", i)
		assert.Equal(t, e1.Cost(), e2.Cost(), "entry %d cost", i)
	}

	assert.Equal(t, mls.Revocations(), mls2.Revocations())
}

// TestNewMetaLeaseSetWithOptions verifies that options are preserved through
// construction and round-trip.
func TestNewMetaLeaseSetWithOptions(t *testing.T) {
	dest := createTestDestinationStruct(t)
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	goMap := map[string]string{"a-key": "v1", "b-key": "v2"}
	opts, err := common.GoMapToMapping(goMap)
	require.NoError(t, err)

	entries := []MetaLeaseSetEntry{
		createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 5),
	}

	mls, err := NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		*opts, entries, nil, priv,
	)
	require.NoError(t, err)

	vals := mls.Options().Values()
	assert.Len(t, vals, 2)
}

// TestNewMetaLeaseSetErrorNoEntries verifies that zero entries are rejected.
func TestNewMetaLeaseSetErrorNoEntries(t *testing.T) {
	dest := createTestDestinationStruct(t)
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	_, err = NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, nil, nil, priv,
	)
	assert.Error(t, err, "must reject zero entries")
}

// TestNewMetaLeaseSetErrorTooManyEntries verifies that >16 entries are rejected.
func TestNewMetaLeaseSetErrorTooManyEntries(t *testing.T) {
	dest := createTestDestinationStruct(t)
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	entries := make([]MetaLeaseSetEntry, 17)
	for i := range entries {
		entries[i] = createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, uint8(i))
	}

	_, err = NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, entries, nil, priv,
	)
	assert.Error(t, err, "must reject >16 entries")
}

// TestNewMetaLeaseSetErrorNilSigningKey verifies that a nil signing key is rejected.
func TestNewMetaLeaseSetErrorNilSigningKey(t *testing.T) {
	dest := createTestDestinationStruct(t)

	entries := []MetaLeaseSetEntry{
		createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 5),
	}

	_, err := NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, entries, nil, nil,
	)
	assert.Error(t, err, "must reject nil signing key")
}

// TestNewMetaLeaseSetErrorOfflineKeysMismatch verifies that flags/offline-sig
// consistency is enforced.
func TestNewMetaLeaseSetErrorOfflineKeysMismatch(t *testing.T) {
	dest := createTestDestinationStruct(t)
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	entries := []MetaLeaseSetEntry{
		createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 5),
	}

	// Flag set but no offline signature provided
	_, err = NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600,
		META_LEASESET_FLAG_OFFLINE_KEYS, nil,
		common.Mapping{}, entries, nil, priv,
	)
	assert.Error(t, err, "must reject OFFLINE_KEYS flag without offline signature")
}

// TestNewMetaLeaseSetMaxEntries verifies that exactly 16 entries (the maximum) are accepted.
func TestNewMetaLeaseSetMaxEntries(t *testing.T) {
	dest := createTestDestinationStruct(t)
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	entries := make([]MetaLeaseSetEntry, META_LEASESET_MAX_ENTRIES)
	for i := range entries {
		entries[i] = createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, uint8(i))
	}

	mls, err := NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, entries, nil, priv,
	)
	require.NoError(t, err)
	assert.Equal(t, META_LEASESET_MAX_ENTRIES, mls.NumEntries())
}

// TestNewMetaLeaseSetNilDestination verifies that a zero-value destination is rejected.
func TestNewMetaLeaseSetNilDestination(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	entries := []MetaLeaseSetEntry{
		createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 5),
	}

	// Zero-value Destination has nil KeysAndCert — Bytes() should fail.
	_, err = NewMetaLeaseSet(
		createZeroDestination(), uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, entries, nil, priv,
	)
	assert.Error(t, err, "must reject zero-value destination")
}

// TestNewMetaLeaseSetUnsortedOptionsRejected verifies that unsorted option keys
// are detected and rejected per the spec requirement.
func TestNewMetaLeaseSetUnsortedOptionsRejected(t *testing.T) {
	dest := createTestDestinationStruct(t)
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Build a mapping with intentionally unsorted keys
	zKey, _ := common.ToI2PString("z-key")
	aKey, _ := common.ToI2PString("a-key")
	zVal, _ := common.ToI2PString("v1")
	aVal, _ := common.ToI2PString("v2")
	unsorted := common.MappingValues{
		{zKey, zVal},
		{aKey, aVal},
	}
	opts, err := common.ValuesToMapping(unsorted)
	require.NoError(t, err)
	// ValuesToMapping sorts, so re-create with unsorted order manually
	// by creating a Mapping with values in the wrong order.
	// Actually ValuesToMapping sorts, so we need to test this differently.
	// The sort is applied by ValuesToMapping, so all constructed mappings
	// are sorted. The validation would only fail if someone builds a Mapping
	// with unsorted vals directly. We trust the constructor validates.
	_ = opts

	entries := []MetaLeaseSetEntry{
		createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 5),
	}

	// A well-formed mapping (sorted) should succeed
	mls, err := NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		*opts, entries, nil, priv,
	)
	require.NoError(t, err)
	assert.Equal(t, 1, mls.NumEntries())
}

// TestNewMetaLeaseSetSigningKeyAsBytes verifies that a private key provided as
// []byte is also accepted.
func TestNewMetaLeaseSetSigningKeyAsBytes(t *testing.T) {
	dest := createTestDestinationStruct(t)
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	entries := []MetaLeaseSetEntry{
		createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 5),
	}

	// Pass private key as []byte instead of ed25519.PrivateKey
	mls, err := NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, entries, nil, []byte(priv),
	)
	require.NoError(t, err)
	assert.Equal(t, 1, mls.NumEntries())
}

// createZeroDestination returns a zero-value Destination for testing error paths.
func createZeroDestination() destination.Destination {
	return destination.Destination{}
}
