package meta_leaseset

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMetaLeaseSetStructExists verifies the package structure is set up correctly
func TestMetaLeaseSetStructExists(t *testing.T) {
	// Verify core constants are defined
	if META_LEASESET_TYPE != 7 {
		t.Errorf("META_LEASESET_TYPE = %d, want 7", META_LEASESET_TYPE)
	}

	if META_LEASESET_MIN_ENTRIES != 1 {
		t.Errorf("META_LEASESET_MIN_ENTRIES = %d, want 1", META_LEASESET_MIN_ENTRIES)
	}

	if META_LEASESET_MAX_ENTRIES != 16 {
		t.Errorf("META_LEASESET_MAX_ENTRIES = %d, want 16", META_LEASESET_MAX_ENTRIES)
	}

	// Verify MIN_SIZE arithmetic:
	// Destination(387) + published(4) + expires(2) + flags(2) + options(2) +
	// num(1) + 1 entry(40) + numr(1) + signature(64) = 503
	assert.Equal(t, 503, META_LEASESET_MIN_SIZE)
	expectedMin := META_LEASESET_MIN_DESTINATION_SIZE +
		META_LEASESET_PUBLISHED_SIZE +
		META_LEASESET_EXPIRES_SIZE +
		META_LEASESET_FLAGS_SIZE +
		2 + // minimum options mapping
		META_LEASESET_NUM_ENTRIES_SIZE +
		META_LEASESET_ENTRY_SIZE +
		META_LEASESET_NUM_REVOCATIONS_SIZE +
		64 // minimum EdDSA signature size
	assert.Equal(t, expectedMin, META_LEASESET_MIN_SIZE)

	// Verify entry size sum: hash(32) + flags(3) + cost(1) + end_date(4) = 40
	assert.Equal(t, META_LEASESET_ENTRY_SIZE,
		META_LEASESET_ENTRY_HASH_SIZE+META_LEASESET_ENTRY_FLAGS_SIZE+
			META_LEASESET_ENTRY_COST_SIZE+META_LEASESET_ENTRY_END_DATE_SIZE)

	// Verify revocation constants
	assert.Equal(t, 1, META_LEASESET_NUM_REVOCATIONS_SIZE)
	assert.Equal(t, 32, META_LEASESET_REVOCATION_HASH_SIZE)

	// Verify DB store type
	assert.Equal(t, 0x07, META_LEASESET_DBSTORE_TYPE)
}

// TestMetaLeaseSetEntryTypes verifies entry type constants
func TestMetaLeaseSetEntryTypes(t *testing.T) {
	tests := []struct {
		name     string
		typeVal  uint8
		expected uint8
	}{
		{"Unknown", META_LEASESET_ENTRY_TYPE_UNKNOWN, 0},
		{"LeaseSet", META_LEASESET_ENTRY_TYPE_LEASESET, 1},
		{"LeaseSet2", META_LEASESET_ENTRY_TYPE_LEASESET2, 3},
		{"MetaLeaseSet", META_LEASESET_ENTRY_TYPE_META_LEASESET, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.typeVal != tt.expected {
				t.Errorf("%s type = %d, want %d", tt.name, tt.typeVal, tt.expected)
			}
		})
	}
}

// TestMetaLeaseSetFlags verifies flag constants
func TestMetaLeaseSetFlags(t *testing.T) {
	if META_LEASESET_FLAG_OFFLINE_KEYS != 0x0001 {
		t.Errorf("META_LEASESET_FLAG_OFFLINE_KEYS = 0x%04x, want 0x0001", META_LEASESET_FLAG_OFFLINE_KEYS)
	}

	if META_LEASESET_FLAG_UNPUBLISHED != 0x0002 {
		t.Errorf("META_LEASESET_FLAG_UNPUBLISHED = 0x%04x, want 0x0002", META_LEASESET_FLAG_UNPUBLISHED)
	}

	if META_LEASESET_FLAG_BLINDED != 0x0004 {
		t.Errorf("META_LEASESET_FLAG_BLINDED = 0x%04x, want 0x0004", META_LEASESET_FLAG_BLINDED)
	}
}

// TestIsBlinded verifies the IsBlinded() accessor against the LeaseSet2Header bit 2 spec.
func TestIsBlinded(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint16
		expected bool
	}{
		{"no flags", 0x0000, false},
		{"offline keys only", META_LEASESET_FLAG_OFFLINE_KEYS, false},
		{"unpublished only", META_LEASESET_FLAG_UNPUBLISHED, false},
		{"blinded only", META_LEASESET_FLAG_BLINDED, true},
		{"blinded + unpublished", META_LEASESET_FLAG_BLINDED | META_LEASESET_FLAG_UNPUBLISHED, true},
		{"all three flags", META_LEASESET_FLAG_OFFLINE_KEYS | META_LEASESET_FLAG_UNPUBLISHED | META_LEASESET_FLAG_BLINDED, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mls := &MetaLeaseSet{flags: tt.flags}
			assert.Equal(t, tt.expected, mls.IsBlinded(), "IsBlinded() mismatch for flags=0x%04x", tt.flags)
		})
	}
}

// createTestDestination creates a minimal valid destination for testing
func createTestDestination(t *testing.T, sigType uint16) []byte {
	t.Helper()
	// Create 384 bytes of keys data (ElGamal 256 + padding 128)
	keysData := make([]byte, 384)
	for i := range keysData {
		keysData[i] = byte(i % 256)
	}

	// Create KEY certificate (type=5) with 4-byte payload
	// Total: 384 + 1 (type) + 2 (length) + 4 (payload) = 391 bytes
	certData := []byte{
		0x05,       // Certificate type = KEY (5)
		0x00, 0x04, // Certificate length = 4 bytes
		0x00, 0x00, // Signing key type (big-endian)
		0x00, 0x00, // Crypto key type = ElGamal (big-endian)
	}

	// Update signing key type
	binary.BigEndian.PutUint16(certData[3:5], sigType)

	return append(keysData, certData...)
}

// createTestEntry creates a test MetaLeaseSetEntry in spec wire format (40 bytes).
// Per spec: hash(32) + flags(3) + cost(1) + end_date(4) = 40 bytes.
func createTestEntry(leaseType uint8, cost uint8) []byte {
	data := make([]byte, 0, META_LEASESET_ENTRY_SIZE)

	// Hash (32 bytes)
	hash := sha256.Sum256([]byte("test entry"))
	data = append(data, hash[:]...)

	// Flags (3 bytes) - entry type in bits 3-0 of byte[2]
	flags := MakeEntryFlags(leaseType)
	data = append(data, flags[:]...)

	// Cost (1 byte)
	data = append(data, cost)

	// End date (4 bytes) - 1 hour from now, seconds since epoch
	endDate := uint32(time.Now().Unix() + 3600)
	endDateBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(endDateBytes, endDate)
	data = append(data, endDateBytes...)

	return data
}

// createTestEntryStruct creates a MetaLeaseSetEntry struct for tests
func createTestEntryStruct(leaseType uint8, cost uint8) MetaLeaseSetEntry {
	hash := sha256.Sum256([]byte(fmt.Sprintf("test entry %d", cost)))
	endDate := uint32(time.Now().Unix() + 3600)

	return MetaLeaseSetEntry{
		hash:    hash,
		flags:   MakeEntryFlags(leaseType),
		cost:    cost,
		endDate: endDate,
	}
}

// createTestDestinationStruct creates a destination.Destination for tests
func createTestDestinationStruct(t *testing.T) destination.Destination {
	t.Helper()
	destBytes := createTestDestination(t, 7) // Ed25519 signature type
	dest, _, err := destination.ReadDestination(destBytes)
	require.NoError(t, err)
	return dest
}

// createTestSignature creates a dummy 64-byte Ed25519 signature for tests
func createTestSignature() signature.Signature {
	// Ed25519 signatures are 64 bytes
	sigBytes := make([]byte, 64)
	for i := range sigBytes {
		sigBytes[i] = byte(i % 256)
	}
	sig, err := signature.NewSignatureFromBytes(sigBytes, key_certificate.KEYCERT_SIGN_ED25519)
	if err != nil {
		panic("createTestSignature: " + err.Error())
	}
	return sig
}

// TestReadMetaLeaseSetMinimalValid tests parsing of a minimal valid MetaLeaseSet
func TestReadMetaLeaseSetMinimalValid(t *testing.T) {
	// Create destination
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	dest, _, err := destination.ReadDestination(destData)
	require.NoError(t, err)

	data := destData

	// Published (4 bytes)
	published := uint32(time.Now().Unix())
	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, published)
	data = append(data, publishedBytes...)

	// Expires (2 bytes)
	expires := uint16(600)
	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, expires)
	data = append(data, expiresBytes...)

	// Flags (2 bytes)
	flags := uint16(0)
	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, flags)
	data = append(data, flagsBytes...)

	// Options (empty mapping = 2 bytes)
	data = append(data, 0x00, 0x00)

	// Number of entries (1 byte)
	numEntries := byte(1)
	data = append(data, numEntries)

	// Entry
	entryData := createTestEntry(META_LEASESET_ENTRY_TYPE_LEASESET2, 10)
	data = append(data, entryData...)

	// Number of revocations (0)
	data = append(data, 0x00)

	// Signature
	signatureData := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	for i := 0; i < signature.EdDSA_SHA512_Ed25519_SIZE; i++ {
		signatureData[i] = byte(0xFF - i)
	}
	data = append(data, signatureData...)

	// Parse
	mls, remainder, err := ReadMetaLeaseSet(data)

	assert.NoError(t, err)
	assert.Empty(t, remainder)
	assert.Equal(t, published, mls.Published())
	assert.Equal(t, expires, mls.Expires())
	assert.Equal(t, flags, mls.Flags())
	assert.False(t, mls.HasOfflineKeys())
	assert.False(t, mls.IsUnpublished())
	assert.Nil(t, mls.OfflineSignature())
	assert.Equal(t, 1, mls.NumEntries())
	destAddr, err := dest.Base32Address()
	assert.NoError(t, err)
	mlsAddr, err := mls.Destination().Base32Address()
	assert.NoError(t, err)
	assert.Equal(t, destAddr, mlsAddr)
}

// TestReadMetaLeaseSetMultipleEntries tests parsing with multiple entries
func TestReadMetaLeaseSetMultipleEntries(t *testing.T) {
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	data := destData

	published := uint32(time.Now().Unix())
	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, published)
	data = append(data, publishedBytes...)

	expires := uint16(3600)
	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, expires)
	data = append(data, expiresBytes...)

	flags := uint16(0)
	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, flags)
	data = append(data, flagsBytes...)

	data = append(data, 0x00, 0x00) // Empty options

	// 3 entries
	numEntries := byte(3)
	data = append(data, numEntries)

	// Different types and costs
	data = append(data, createTestEntry(META_LEASESET_ENTRY_TYPE_LEASESET, 5)...)
	data = append(data, createTestEntry(META_LEASESET_ENTRY_TYPE_LEASESET2, 10)...)
	data = append(data, createTestEntry(META_LEASESET_ENTRY_TYPE_META_LEASESET, 15)...)

	// Number of revocations (0)
	data = append(data, 0x00)

	signatureData := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	data = append(data, signatureData...)

	mls, remainder, err := ReadMetaLeaseSet(data)

	assert.NoError(t, err)
	assert.Empty(t, remainder)
	assert.Equal(t, 3, mls.NumEntries())

	entries := mls.Entries()
	assert.Equal(t, uint8(META_LEASESET_ENTRY_TYPE_LEASESET), entries[0].Type())
	assert.Equal(t, uint8(META_LEASESET_ENTRY_TYPE_LEASESET2), entries[1].Type())
	assert.Equal(t, uint8(META_LEASESET_ENTRY_TYPE_META_LEASESET), entries[2].Type())
}

// TestReadMetaLeaseSetTooShort tests error handling for insufficient data
func TestReadMetaLeaseSetTooShort(t *testing.T) {
	data := make([]byte, 100)
	_, _, err := ReadMetaLeaseSet(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// TestReadMetaLeaseSetInvalidEntryCount tests error handling for invalid entry count
func TestReadMetaLeaseSetInvalidEntryCount(t *testing.T) {
	tests := []struct {
		name       string
		numEntries byte
	}{
		{"zero entries", 0},
		{"too many entries", 17},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
			data := destData

			published := uint32(time.Now().Unix())
			publishedBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(publishedBytes, published)
			data = append(data, publishedBytes...)

			expires := uint16(600)
			expiresBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(expiresBytes, expires)
			data = append(data, expiresBytes...)

			flags := uint16(0)
			flagsBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(flagsBytes, flags)
			data = append(data, flagsBytes...)

			data = append(data, 0x00, 0x00) // Empty options
			data = append(data, tt.numEntries)

			_, _, err := ReadMetaLeaseSet(data)
			assert.Error(t, err)
		})
	}
}

// TestReadMetaLeaseSetInvalidEntryType tests error handling for invalid entry type
// TestReadMetaLeaseSetInvalidEntryType verifies forward-compatible handling of unknown
// MetaLease entry types. Per the AUDIT fix, unrecognised type values (e.g. 2, 4, 7)
// must no longer cause a hard parse failure; they are accepted with a warning so that
// future spec revisions or non-conforming peers do not break parsing.
func TestReadMetaLeaseSetInvalidEntryType(t *testing.T) {
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	data := destData

	published := uint32(time.Now().Unix())
	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, published)
	data = append(data, publishedBytes...)

	expires := uint16(600)
	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, expires)
	data = append(data, expiresBytes...)

	flags := uint16(0)
	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, flags)
	data = append(data, flagsBytes...)

	data = append(data, 0x00, 0x00) // Empty options
	data = append(data, byte(1))    // 1 entry

	// Type 7 is currently undefined in the spec — must be accepted for forward compatibility.
	unknownEntry := createTestEntry(7, 10)
	data = append(data, unknownEntry...)

	data = append(data, 0x00)               // 0 revocations
	sigBytes := make([]byte, 64)
	data = append(data, sigBytes...)        // dummy Ed25519 signature

	mls, _, err := ReadMetaLeaseSet(data)
	// Forward-compatible: must NOT fail on unknown entry type.
	require	.NoError(t, err)
	require.Equal(t, 1, mls.NumEntries())
	// The raw type bits should still be preserved in the entry flags.
	assert.Equal(t, uint8(7), mls.Entries()[0].Type())
}

// TestMetaLeaseSetFindEntriesByType tests filtering entries by type
func TestMetaLeaseSetFindEntriesByType(t *testing.T) {
	mls := &MetaLeaseSet{
		entries: []MetaLeaseSetEntry{
			{flags: MakeEntryFlags(META_LEASESET_ENTRY_TYPE_LEASESET), cost: 1},
			{flags: MakeEntryFlags(META_LEASESET_ENTRY_TYPE_LEASESET2), cost: 2},
			{flags: MakeEntryFlags(META_LEASESET_ENTRY_TYPE_LEASESET), cost: 3},
			{flags: MakeEntryFlags(META_LEASESET_ENTRY_TYPE_META_LEASESET), cost: 4},
			{flags: MakeEntryFlags(META_LEASESET_ENTRY_TYPE_LEASESET2), cost: 5},
		},
	}

	// Find LeaseSet entries
	lsEntries := mls.FindEntriesByType(META_LEASESET_ENTRY_TYPE_LEASESET)
	assert.Equal(t, 2, len(lsEntries))

	// Find LeaseSet2 entries
	ls2Entries := mls.FindEntriesByType(META_LEASESET_ENTRY_TYPE_LEASESET2)
	assert.Equal(t, 2, len(ls2Entries))

	// Find MetaLeaseSet entries
	metaEntries := mls.FindEntriesByType(META_LEASESET_ENTRY_TYPE_META_LEASESET)
	assert.Equal(t, 1, len(metaEntries))
}

// TestMetaLeaseSetSortEntriesByCost tests sorting entries by cost
func TestMetaLeaseSetSortEntriesByCost(t *testing.T) {
	mls := &MetaLeaseSet{
		entries: []MetaLeaseSetEntry{
			{cost: 15, flags: MakeEntryFlags(META_LEASESET_ENTRY_TYPE_LEASESET)},
			{cost: 5, flags: MakeEntryFlags(META_LEASESET_ENTRY_TYPE_LEASESET2)},
			{cost: 10, flags: MakeEntryFlags(META_LEASESET_ENTRY_TYPE_META_LEASESET)},
			{cost: 1, flags: MakeEntryFlags(META_LEASESET_ENTRY_TYPE_LEASESET2)},
		},
	}

	sorted := mls.SortEntriesByCost()

	assert.Equal(t, 4, len(sorted))
	assert.Equal(t, uint8(1), sorted[0].Cost())
	assert.Equal(t, uint8(5), sorted[1].Cost())
	assert.Equal(t, uint8(10), sorted[2].Cost())
	assert.Equal(t, uint8(15), sorted[3].Cost())

	// Verify original is unchanged
	assert.Equal(t, uint8(15), mls.entries[0].cost)
}

// TestMetaLeaseSetGetEntry tests GetEntry method
func TestMetaLeaseSetGetEntry(t *testing.T) {
	mls := &MetaLeaseSet{
		numEntries: 3,
		entries: []MetaLeaseSetEntry{
			{cost: 10},
			{cost: 20},
			{cost: 30},
		},
	}

	// Valid indices
	entry, err := mls.GetEntry(0)
	assert.NoError(t, err)
	assert.Equal(t, uint8(10), entry.Cost())

	entry, err = mls.GetEntry(2)
	assert.NoError(t, err)
	assert.Equal(t, uint8(30), entry.Cost())

	// Invalid indices
	_, err = mls.GetEntry(-1)
	assert.Error(t, err)

	_, err = mls.GetEntry(3)
	assert.Error(t, err)
}

// TestMetaLeaseSetExpirationCheck tests expiration checking
func TestMetaLeaseSetExpirationCheck(t *testing.T) {
	// Expired MetaLeaseSet
	pastTime := uint32(time.Now().Unix() - 3600)
	mls := &MetaLeaseSet{published: pastTime, expires: 600}
	assert.True(t, mls.IsExpired())

	// Valid MetaLeaseSet
	nowTime := uint32(time.Now().Unix())
	mls2 := &MetaLeaseSet{published: nowTime, expires: 3600}
	assert.False(t, mls2.IsExpired())
}

// TestMetaLeaseSetEntryExpiration tests entry expiration checking
func TestMetaLeaseSetEntryExpiration(t *testing.T) {
	// Expired entry
	pastTime := uint32(time.Now().Unix() - 100)
	entry := MetaLeaseSetEntry{endDate: pastTime}
	assert.True(t, entry.IsExpired())

	// Valid entry
	futureTime := uint32(time.Now().Unix() + 3600)
	entry2 := MetaLeaseSetEntry{endDate: futureTime}
	assert.False(t, entry2.IsExpired())
}

// TestMetaLeaseSetFlags tests flag checking methods
func TestMetaLeaseSetFlagsCheck(t *testing.T) {
	tests := []struct {
		name              string
		flags             uint16
		expectOfflineKeys bool
		expectUnpublished bool
	}{
		{"no flags", 0x0000, false, false},
		{"offline keys only", META_LEASESET_FLAG_OFFLINE_KEYS, true, false},
		{"unpublished only", META_LEASESET_FLAG_UNPUBLISHED, false, true},
		{"both flags", META_LEASESET_FLAG_OFFLINE_KEYS | META_LEASESET_FLAG_UNPUBLISHED, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mls := &MetaLeaseSet{flags: tt.flags}
			assert.Equal(t, tt.expectOfflineKeys, mls.HasOfflineKeys())
			assert.Equal(t, tt.expectUnpublished, mls.IsUnpublished())
		})
	}
}

// TestMetaLeaseSetAccessors tests basic accessor methods
func TestMetaLeaseSetAccessors(t *testing.T) {
	published := uint32(1735689600)
	expires := uint16(3600)
	flags := uint16(META_LEASESET_FLAG_UNPUBLISHED)

	mls := &MetaLeaseSet{
		published: published,
		expires:   expires,
		flags:     flags,
		options:   common.Mapping{},
	}

	assert.Equal(t, published, mls.Published())
	assert.Equal(t, expires, mls.Expires())
	assert.Equal(t, flags, mls.Flags())
	assert.NotNil(t, mls.Options())

	publishedTime := mls.PublishedTime()
	assert.Equal(t, int64(published), publishedTime.Unix())

	expirationTime := mls.ExpirationTime()
	expectedExpiration := time.Unix(int64(published), 0).Add(time.Duration(expires) * time.Second)
	assert.Equal(t, expectedExpiration.Unix(), expirationTime.Unix())
}

// TestMetaLeaseSetEntryAccessors tests entry accessor methods
func TestMetaLeaseSetEntryAccessors(t *testing.T) {
	hash := sha256.Sum256([]byte("test"))
	endDate := uint32(time.Now().Unix() + 3600)
	cost := uint8(42)
	leaseType := uint8(META_LEASESET_ENTRY_TYPE_LEASESET2)

	entry := MetaLeaseSetEntry{
		hash:    hash,
		flags:   MakeEntryFlags(leaseType),
		endDate: endDate,
		cost:    cost,
	}

	assert.Equal(t, hash, entry.Hash())
	assert.Equal(t, leaseType, entry.Type())
	assert.Equal(t, endDate, entry.Expires())
	assert.Equal(t, cost, entry.Cost())
	assert.Equal(t, MakeEntryFlags(leaseType), entry.Flags())

	expiresTime := entry.ExpiresTime()
	assert.Equal(t, int64(endDate), expiresTime.Unix())
}

// TestMetaLeaseSetEntryBytes tests entry serialization
func TestMetaLeaseSetEntryBytes(t *testing.T) {
	hash := sha256.Sum256([]byte("test hash"))
	endDate := uint32(time.Now().Unix() + 3600)
	cost := uint8(10)
	leaseType := uint8(META_LEASESET_ENTRY_TYPE_LEASESET2)

	entry := MetaLeaseSetEntry{
		hash:    hash,
		flags:   MakeEntryFlags(leaseType),
		cost:    cost,
		endDate: endDate,
	}

	bytes, err := entry.Bytes()
	assert.NoError(t, err)

	// Verify size: hash(32) + flags(3) + cost(1) + end_date(4) = 40 bytes
	assert.Equal(t, META_LEASESET_ENTRY_SIZE, len(bytes))

	// Verify hash (bytes 0-31)
	assert.Equal(t, hash[:], bytes[0:32])

	// Verify flags (bytes 32-34), type in byte[34] bits 3-0
	assert.Equal(t, byte(0), bytes[32])
	assert.Equal(t, byte(0), bytes[33])
	assert.Equal(t, leaseType, bytes[34]&0x0F)

	// Verify cost (byte 35)
	assert.Equal(t, cost, bytes[35])

	// Verify end_date (bytes 36-39)
	parsedEndDate := binary.BigEndian.Uint32(bytes[36:40])
	assert.Equal(t, endDate, parsedEndDate)
}

// TestMetaLeaseSetBytes tests MetaLeaseSet serialization
func TestMetaLeaseSetBytes(t *testing.T) {
	dest := createTestDestinationStruct(t)
	published := uint32(time.Now().Unix())
	expires := uint16(600)

	// Create test entries
	entry1 := createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 10)
	entry2 := createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET, 20)

	mls := MetaLeaseSet{
		destination:      dest,
		published:        published,
		expires:          expires,
		flags:            0,
		offlineSignature: nil,
		options:          common.Mapping{},
		numEntries:       2,
		entries:          []MetaLeaseSetEntry{entry1, entry2},
		signature:        createTestSignature(),
	}

	bytes, err := mls.Bytes()
	assert.NoError(t, err)
	assert.NotEmpty(t, bytes)

	// Verify minimum expected size
	// dest(391) + published(4) + expires(2) + flags(2) + options(2) + numEntries(1) + 2*entry(40) + numr(1) + sig(64) = 547
	assert.GreaterOrEqual(t, len(bytes), 547)

	// Verify structure by checking key positions
	// Published should be at offset 391
	parsedPublished := binary.BigEndian.Uint32(bytes[391:395])
	assert.Equal(t, published, parsedPublished)

	// Expires should be at offset 395
	parsedExpires := binary.BigEndian.Uint16(bytes[395:397])
	assert.Equal(t, expires, parsedExpires)

	// Flags should be at offset 397
	parsedFlags := binary.BigEndian.Uint16(bytes[397:399])
	assert.Equal(t, uint16(0), parsedFlags)
}

// TestMetaLeaseSetSerializationConsistency tests that serialization is deterministic
func TestMetaLeaseSetSerializationConsistency(t *testing.T) {
	dest := createTestDestinationStruct(t)
	published := uint32(time.Now().Unix())
	expires := uint16(600)

	entry1 := createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 10)
	entry2 := createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET, 20)

	// Create MetaLeaseSet
	mls := MetaLeaseSet{
		destination:      dest,
		published:        published,
		expires:          expires,
		flags:            0,
		offlineSignature: nil,
		options:          common.Mapping{},
		numEntries:       2,
		entries:          []MetaLeaseSetEntry{entry1, entry2},
		signature:        createTestSignature(),
	}

	// Serialize twice and verify byte-for-byte equality
	bytes1, err1 := mls.Bytes()
	assert.NoError(t, err1)

	bytes2, err2 := mls.Bytes()
	assert.NoError(t, err2)

	assert.Equal(t, bytes1, bytes2, "Serialization should be deterministic")
	assert.Equal(t, len(bytes1), len(bytes2))
}

// TestMetaLeaseSetBytesWithRevocations tests serialization with revocation hashes
func TestMetaLeaseSetBytesWithRevocations(t *testing.T) {
	dest := createTestDestinationStruct(t)
	published := uint32(time.Now().Unix())
	expires := uint16(600)

	// Create entry
	entry := createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 5)

	// Create revocation hashes
	rev1 := sha256.Sum256([]byte("revoked lease set 1"))
	rev2 := sha256.Sum256([]byte("revoked lease set 2"))

	mls := MetaLeaseSet{
		destination:      dest,
		published:        published,
		expires:          expires,
		flags:            0,
		offlineSignature: nil,
		options:          common.Mapping{},
		numEntries:       1,
		entries:          []MetaLeaseSetEntry{entry},
		numRevocations:   2,
		revocations:      [][32]byte{rev1, rev2},
		signature:        createTestSignature(),
	}

	bytes, err := mls.Bytes()
	assert.NoError(t, err)
	assert.NotEmpty(t, bytes)

	// Verify size includes revocations
	// dest(391) + published(4) + expires(2) + flags(2) + options(2) + numEntries(1) + 1*entry(40) + numr(1) + 2*hash(64) + sig(64) = 571
	assert.GreaterOrEqual(t, len(bytes), 571)

	// Verify NumRevocations and Revocations accessors
	assert.Equal(t, 2, mls.NumRevocations())
	revs := mls.Revocations()
	assert.Equal(t, 2, len(revs))
	assert.Equal(t, rev1, revs[0])
	assert.Equal(t, rev2, revs[1])

	// Test GetRevocation
	r0, err := mls.GetRevocation(0)
	assert.NoError(t, err)
	assert.Equal(t, rev1, r0)

	r1, err := mls.GetRevocation(1)
	assert.NoError(t, err)
	assert.Equal(t, rev2, r1)

	// Test out of range
	_, err = mls.GetRevocation(2)
	assert.Error(t, err)
}

// TestMetaLeaseSetValidateEntryTypes tests that validateEntryType accepts all spec-valid
// types (0, 1, 3, 5) and rejects invalid ones.
// TestMetaLeaseSetValidateEntryTypes verifies that validateEntryType accepts known
// types without error and accepts unknown types with a warning (forward-compatible).
func TestMetaLeaseSetValidateEntryTypes(t *testing.T) {
	validTypes := []struct {
		name    string
		typeVal uint8
	}{
		{"unknown", META_LEASESET_ENTRY_TYPE_UNKNOWN},
		{"LeaseSet", META_LEASESET_ENTRY_TYPE_LEASESET},
		{"LeaseSet2", META_LEASESET_ENTRY_TYPE_LEASESET2},
		{"MetaLeaseSet", META_LEASESET_ENTRY_TYPE_META_LEASESET},
	}

	for _, vt := range validTypes {
		t.Run(vt.name, func(t *testing.T) {
			err := validateEntryType(vt.typeVal, 0)
			assert.NoError(t, err, "type %d (%s) must be accepted", vt.typeVal, vt.name)
		})
	}

	// Unrecognised/reserved types must also be accepted for forward compatibility.
	// The previous behaviour (hard error) broke parsing against future spec revisions.
	reservedTypes := []uint8{2, 4, 6, 7, 8, 15}
	for _, it := range reservedTypes {
		t.Run(fmt.Sprintf("reserved_%d", it), func(t *testing.T) {
			err := validateEntryType(it, 0)
			assert.NoError(t, err, "reserved type %d must be forwarded-compatible (no error)", it)
		})
	}
}

// TestMetaLeaseSetTypeExtractsFromFlags verifies that Type() correctly extracts
// bits 3-0 from flags[2], ignoring reserved upper bits.
func TestMetaLeaseSetTypeExtractsFromFlags(t *testing.T) {
	tests := []struct {
		name     string
		flags    [3]byte
		expected uint8
	}{
		{"type 0", [3]byte{0, 0, 0x00}, 0},
		{"type 1", [3]byte{0, 0, 0x01}, 1},
		{"type 3", [3]byte{0, 0, 0x03}, 3},
		{"type 5", [3]byte{0, 0, 0x05}, 5},
		{"type 5 with upper bits", [3]byte{0xFF, 0xFF, 0xF5}, 5},
		{"type 1 with reserved bits", [3]byte{0xAB, 0xCD, 0xE1}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := MetaLeaseSetEntry{flags: tt.flags}
			assert.Equal(t, tt.expected, entry.Type(),
				"Type() must extract bits 3-0 of flags[2]")
		})
	}
}

// TestMetaLeaseSetMakeEntryFlags tests the MakeEntryFlags helper
func TestMetaLeaseSetMakeEntryFlags(t *testing.T) {
	flags := MakeEntryFlags(3)
	assert.Equal(t, [3]byte{0, 0, 3}, flags)

	// Only low nibble should be set
	flags = MakeEntryFlags(0xFF)
	assert.Equal(t, [3]byte{0, 0, 0x0F}, flags,
		"MakeEntryFlags should mask to bits 3-0")
}

// TestMetaLeaseSetRoundTrip verifies parse → serialize → parse consistency.
func TestMetaLeaseSetRoundTrip(t *testing.T) {
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	data := destData

	published := uint32(1700000000) // fixed timestamp
	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, published)
	data = append(data, publishedBytes...)

	expires := uint16(3600)
	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, expires)
	data = append(data, expiresBytes...)

	data = append(data, 0x00, 0x00) // flags = 0
	data = append(data, 0x00, 0x00) // empty options

	// 2 entries
	data = append(data, 0x02)
	data = append(data, createTestEntry(META_LEASESET_ENTRY_TYPE_LEASESET, 5)...)
	data = append(data, createTestEntry(META_LEASESET_ENTRY_TYPE_LEASESET2, 15)...)

	// 1 revocation
	data = append(data, 0x01)
	rev := sha256.Sum256([]byte("revoked dest"))
	data = append(data, rev[:]...)

	// Signature
	sigBytes := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	for i := range sigBytes {
		sigBytes[i] = byte(i)
	}
	data = append(data, sigBytes...)

	// Parse
	mls, remainder, err := ReadMetaLeaseSet(data)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	// Re-serialize
	reserialized, err := mls.Bytes()
	require.NoError(t, err)

	// Re-parse
	mls2, remainder2, err := ReadMetaLeaseSet(reserialized)
	require.NoError(t, err)
	assert.Empty(t, remainder2)

	// Compare fields
	assert.Equal(t, mls.Published(), mls2.Published())
	assert.Equal(t, mls.Expires(), mls2.Expires())
	assert.Equal(t, mls.Flags(), mls2.Flags())
	assert.Equal(t, mls.NumEntries(), mls2.NumEntries())
	assert.Equal(t, mls.NumRevocations(), mls2.NumRevocations())

	for i := 0; i < mls.NumEntries(); i++ {
		e1, _ := mls.GetEntry(i)
		e2, _ := mls2.GetEntry(i)
		assert.Equal(t, e1.Hash(), e2.Hash(), "entry %d hash", i)
		assert.Equal(t, e1.Type(), e2.Type(), "entry %d type", i)
		assert.Equal(t, e1.Cost(), e2.Cost(), "entry %d cost", i)
		assert.Equal(t, e1.Expires(), e2.Expires(), "entry %d end_date", i)
		assert.Equal(t, e1.Flags(), e2.Flags(), "entry %d flags", i)
	}

	revs1 := mls.Revocations()
	revs2 := mls2.Revocations()
	assert.Equal(t, revs1, revs2, "revocation hashes must match")
}

// TestReadMetaLeaseSetWithRevocations tests parsing a MetaLeaseSet that contains revocations.
func TestReadMetaLeaseSetWithRevocations(t *testing.T) {
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	data := destData

	published := uint32(time.Now().Unix())
	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, published)
	data = append(data, publishedBytes...)

	expires := uint16(600)
	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, expires)
	data = append(data, expiresBytes...)

	data = append(data, 0x00, 0x00) // flags = 0
	data = append(data, 0x00, 0x00) // empty options

	// 1 entry
	data = append(data, 0x01)
	data = append(data, createTestEntry(META_LEASESET_ENTRY_TYPE_LEASESET, 10)...)

	// 2 revocations
	data = append(data, 0x02)
	rev1 := sha256.Sum256([]byte("revoked 1"))
	rev2 := sha256.Sum256([]byte("revoked 2"))
	data = append(data, rev1[:]...)
	data = append(data, rev2[:]...)

	// Signature
	sigBytes := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	data = append(data, sigBytes...)

	mls, remainder, err := ReadMetaLeaseSet(data)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	assert.Equal(t, 2, mls.NumRevocations())
	revs := mls.Revocations()
	require.Equal(t, 2, len(revs))
	assert.Equal(t, rev1, revs[0])
	assert.Equal(t, rev2, revs[1])

	r0, err := mls.GetRevocation(0)
	assert.NoError(t, err)
	assert.Equal(t, rev1, r0)
}

// TestMetaLeaseSetRevocationsTruncatedData tests error handling for malformed revocation data.
func TestMetaLeaseSetRevocationsTruncatedData(t *testing.T) {
	mls := &MetaLeaseSet{}

	// Missing numr byte entirely
	_, err := parseRevocations(mls, []byte{})
	assert.Error(t, err, "empty data should fail")

	// numr=1 but no hash data
	_, err = parseRevocations(mls, []byte{0x01})
	assert.Error(t, err, "numr=1 with no hash data should fail")

	// numr=1 with partial hash (only 16 bytes instead of 32)
	partial := make([]byte, 17)
	partial[0] = 0x01
	_, err = parseRevocations(mls, partial)
	assert.Error(t, err, "numr=1 with partial hash should fail")
}

// TestReadMetaLeaseSetAllEntryTypes tests parsing with all valid entry types including type 0.
func TestReadMetaLeaseSetAllEntryTypes(t *testing.T) {
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	data := destData

	published := uint32(time.Now().Unix())
	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, published)
	data = append(data, publishedBytes...)

	data = append(data, 0x02, 0x58) // expires = 600
	data = append(data, 0x00, 0x00) // flags = 0
	data = append(data, 0x00, 0x00) // empty options

	// 4 entries with all valid types
	data = append(data, 0x04)
	data = append(data, createTestEntry(META_LEASESET_ENTRY_TYPE_UNKNOWN, 1)...)
	data = append(data, createTestEntry(META_LEASESET_ENTRY_TYPE_LEASESET, 5)...)
	data = append(data, createTestEntry(META_LEASESET_ENTRY_TYPE_LEASESET2, 10)...)
	data = append(data, createTestEntry(META_LEASESET_ENTRY_TYPE_META_LEASESET, 15)...)

	// 0 revocations
	data = append(data, 0x00)

	// Signature
	sigBytes := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	data = append(data, sigBytes...)

	mls, remainder, err := ReadMetaLeaseSet(data)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	assert.Equal(t, 4, mls.NumEntries())
	entries := mls.Entries()
	assert.Equal(t, uint8(0), entries[0].Type()) // unknown
	assert.Equal(t, uint8(1), entries[1].Type()) // LeaseSet
	assert.Equal(t, uint8(3), entries[2].Type()) // LeaseSet2
	assert.Equal(t, uint8(5), entries[3].Type()) // MetaLeaseSet

	assert.Equal(t, uint8(1), entries[0].Cost())
	assert.Equal(t, uint8(5), entries[1].Cost())
	assert.Equal(t, uint8(10), entries[2].Cost())
	assert.Equal(t, uint8(15), entries[3].Cost())

	// Verify entry size is exactly 40 bytes for all types
	for i, e := range entries {
		b, err := e.Bytes()
		require.NoError(t, err)
		assert.Equal(t, META_LEASESET_ENTRY_SIZE, len(b), "entry %d must be exactly 40 bytes", i)
	}
}
// TestBytesNilDestinationReturnsError verifies that Bytes() returns an error
// (rather than panicking) when the embedded Destination has a nil KeysAndCert.
// This covers the AUDIT BUG fix: Bytes() now calls mls.destination.Bytes()
// which guards against nil, instead of mls.destination.KeysAndCert.Bytes().
func TestBytesNilDestinationReturnsError(t *testing.T) {
	mls := MetaLeaseSet{
		// destination is zero-value: KeysAndCert is nil
		published: 1700000000,
		expires:   600,
		flags:     0,
	}
	_, err := mls.Bytes()
	assert.Error(t, err, "Bytes() must return an error, not panic, when Destination.KeysAndCert is nil")
}

// TestVerifyReturnsMismatchErrorForZeroSignature verifies that Verify() returns
// an error when the stored signature does not match the data (tampered/zero sig).
// This provides the minimum required test coverage for verify.go.
func TestVerifyReturnsMismatchErrorForZeroSignature(t *testing.T) {
	// Build a syntactically valid MetaLeaseSet from bytes, then call Verify().
	// The signature is all-zeros, which will not verify against any real key.
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	data := destData

	published := uint32(1700000000)
	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, published)
	data = append(data, publishedBytes...)

	data = append(data, 0x02, 0x58) // expires = 600
	data = append(data, 0x00, 0x00) // flags = 0
	data = append(data, 0x00, 0x00) // empty options

	data = append(data, 0x01) // 1 entry
	data = append(data, createTestEntry(META_LEASESET_ENTRY_TYPE_LEASESET2, 5)...)
	data = append(data, 0x00) // 0 revocations

	// All-zero Ed25519 signature — will not verify.
	sigBytes := make([]byte, 64)
	data = append(data, sigBytes...)

	mls, _, err := ReadMetaLeaseSet(data)
	require.NoError(t, err, "parsing must succeed with a syntactically valid byte stream")

	verifyErr := mls.Verify()
	assert.Error(t, verifyErr, "Verify() must return an error when the signature is zeros (not a valid sig)")
}

// TestVerifyNilDestinationErrors verifies that Verify() returns an error rather
// than panicking when called on a zero-value MetaLeaseSet with nil fields.
func TestVerifyNilDestinationErrors(t *testing.T) {
	mls := MetaLeaseSet{}
	err := mls.Verify()
	assert.Error(t, err, "Verify() must return an error for an uninitialised MetaLeaseSet")
}

// TestBytesOptionsSorted verifies that Bytes() serialises the options mapping in
// canonical key order (Java String.compareTo() Unicode code-point order) as
// required by the I2P spec for signature invariance.
func TestBytesOptionsSorted(t *testing.T) {
	// Build a MetaLeaseSet with options intentionally added out of order.
	dest := createTestDestinationStruct(t)

	// Create an options mapping with keys out of alphabetical order.
	goMap := map[string]string{
		"z-key": "v1",
		"a-key": "v2",
		"m-key": "v3",
	}
	opts, err := common.GoMapToMapping(goMap)
	require.NoError(t, err)

	mls := MetaLeaseSet{
		destination:  dest,
		published:    1700000000,
		expires:      600,
		flags:        0,
		options:      *opts,
		numEntries:   1,
		entries:      []MetaLeaseSetEntry{createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 5)},
		numRevocations: 0,
		signature:    createTestSignature(),
	}

	serialized, err := mls.Bytes()
	require.NoError(t, err)

	// Re-parse the serialized form and extract option keys.
	mls2, _, err := ReadMetaLeaseSet(serialized)
	require.NoError(t, err)

	vals := mls2.Options().Values()
	require.Len(t, vals, 3)

	keys := make([]string, len(vals))
	for i, pair := range vals {
		k, kErr := pair[0].Data()
		require.NoError(t, kErr)
		keys[i] = k
	}

	// Keys must be in ascending Unicode code-point order.
	assert.Equal(t, []string{"a-key", "m-key", "z-key"}, keys,
		"Bytes() must output options in sorted key order for signature invariance")
}