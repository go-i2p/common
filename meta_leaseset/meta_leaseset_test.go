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
	// Verify constants are defined
	if META_LEASESET_TYPE != 7 {
		t.Errorf("META_LEASESET_TYPE = %d, want 7", META_LEASESET_TYPE)
	}

	if META_LEASESET_MIN_ENTRIES != 1 {
		t.Errorf("META_LEASESET_MIN_ENTRIES = %d, want 1", META_LEASESET_MIN_ENTRIES)
	}

	if META_LEASESET_MAX_ENTRIES != 16 {
		t.Errorf("META_LEASESET_MAX_ENTRIES = %d, want 16", META_LEASESET_MAX_ENTRIES)
	}
}

// TestMetaLeaseSetEntryTypes verifies entry type constants
func TestMetaLeaseSetEntryTypes(t *testing.T) {
	tests := []struct {
		name     string
		typeVal  uint8
		expected uint8
	}{
		{"LeaseSet", META_LEASESET_ENTRY_TYPE_LEASESET, 1},
		{"LeaseSet2", META_LEASESET_ENTRY_TYPE_LEASESET2, 3},
		{"EncryptedLeaseSet", META_LEASESET_ENTRY_TYPE_ENCRYPTED, 5},
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

// createTestEntry creates a test MetaLeaseSetEntry
func createTestEntry(leaseType uint8, cost uint8) []byte {
	data := make([]byte, 0)

	// Hash (32 bytes)
	hash := sha256.Sum256([]byte("test entry"))
	data = append(data, hash[:]...)

	// Type (1 byte)
	data = append(data, leaseType)

	// Expires (4 bytes) - 1 hour from now
	expires := uint32(time.Now().Unix() + 3600)
	expiresBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(expiresBytes, expires)
	data = append(data, expiresBytes...)

	// Cost (1 byte)
	data = append(data, cost)

	// Properties (empty mapping = 2 bytes)
	data = append(data, 0x00, 0x00)

	return data
}

// createTestEntryStruct creates a MetaLeaseSetEntry struct for tests
func createTestEntryStruct(leaseType uint8, cost uint8) MetaLeaseSetEntry {
	hash := sha256.Sum256([]byte(fmt.Sprintf("test entry %d", cost)))
	expires := uint32(time.Now().Unix() + 3600)

	return MetaLeaseSetEntry{
		hash:       hash,
		leaseType:  leaseType,
		expires:    expires,
		cost:       cost,
		properties: common.Mapping{},
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
	data = append(data, createTestEntry(META_LEASESET_ENTRY_TYPE_ENCRYPTED, 15)...)

	signatureData := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	data = append(data, signatureData...)

	mls, remainder, err := ReadMetaLeaseSet(data)

	assert.NoError(t, err)
	assert.Empty(t, remainder)
	assert.Equal(t, 3, mls.NumEntries())

	entries := mls.Entries()
	assert.Equal(t, uint8(META_LEASESET_ENTRY_TYPE_LEASESET), entries[0].Type())
	assert.Equal(t, uint8(META_LEASESET_ENTRY_TYPE_LEASESET2), entries[1].Type())
	assert.Equal(t, uint8(META_LEASESET_ENTRY_TYPE_ENCRYPTED), entries[2].Type())
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

	// Create entry with invalid type (7 is not valid, only 1, 3, 5)
	invalidEntry := createTestEntry(7, 10)
	data = append(data, invalidEntry...)

	// Add signature (64 bytes for Ed25519)
	sigBytes := make([]byte, 64)
	data = append(data, sigBytes...)

	_, _, err := ReadMetaLeaseSet(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid lease set type")
}

// TestMetaLeaseSetFindEntriesByType tests filtering entries by type
func TestMetaLeaseSetFindEntriesByType(t *testing.T) {
	mls := &MetaLeaseSet{
		entries: []MetaLeaseSetEntry{
			{leaseType: META_LEASESET_ENTRY_TYPE_LEASESET, cost: 1},
			{leaseType: META_LEASESET_ENTRY_TYPE_LEASESET2, cost: 2},
			{leaseType: META_LEASESET_ENTRY_TYPE_LEASESET, cost: 3},
			{leaseType: META_LEASESET_ENTRY_TYPE_ENCRYPTED, cost: 4},
			{leaseType: META_LEASESET_ENTRY_TYPE_LEASESET2, cost: 5},
		},
	}

	// Find LeaseSet entries
	lsEntries := mls.FindEntriesByType(META_LEASESET_ENTRY_TYPE_LEASESET)
	assert.Equal(t, 2, len(lsEntries))

	// Find LeaseSet2 entries
	ls2Entries := mls.FindEntriesByType(META_LEASESET_ENTRY_TYPE_LEASESET2)
	assert.Equal(t, 2, len(ls2Entries))

	// Find EncryptedLeaseSet entries
	encEntries := mls.FindEntriesByType(META_LEASESET_ENTRY_TYPE_ENCRYPTED)
	assert.Equal(t, 1, len(encEntries))
}

// TestMetaLeaseSetSortEntriesByCost tests sorting entries by cost
func TestMetaLeaseSetSortEntriesByCost(t *testing.T) {
	mls := &MetaLeaseSet{
		entries: []MetaLeaseSetEntry{
			{cost: 15, leaseType: META_LEASESET_ENTRY_TYPE_LEASESET},
			{cost: 5, leaseType: META_LEASESET_ENTRY_TYPE_LEASESET2},
			{cost: 10, leaseType: META_LEASESET_ENTRY_TYPE_ENCRYPTED},
			{cost: 1, leaseType: META_LEASESET_ENTRY_TYPE_LEASESET2},
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
	entry := MetaLeaseSetEntry{expires: pastTime}
	assert.True(t, entry.IsExpired())

	// Valid entry
	futureTime := uint32(time.Now().Unix() + 3600)
	entry2 := MetaLeaseSetEntry{expires: futureTime}
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
	expires := uint32(time.Now().Unix() + 3600)
	cost := uint8(42)
	leaseType := uint8(META_LEASESET_ENTRY_TYPE_LEASESET2)

	entry := MetaLeaseSetEntry{
		hash:       hash,
		leaseType:  leaseType,
		expires:    expires,
		cost:       cost,
		properties: common.Mapping{},
	}

	assert.Equal(t, hash, entry.Hash())
	assert.Equal(t, leaseType, entry.Type())
	assert.Equal(t, expires, entry.Expires())
	assert.Equal(t, cost, entry.Cost())
	assert.NotNil(t, entry.Properties())

	expiresTime := entry.ExpiresTime()
	assert.Equal(t, int64(expires), expiresTime.Unix())
}

// TestMetaLeaseSetEntryBytes tests entry serialization
func TestMetaLeaseSetEntryBytes(t *testing.T) {
	hash := sha256.Sum256([]byte("test hash"))
	expires := uint32(time.Now().Unix() + 3600)
	cost := uint8(10)
	leaseType := uint8(META_LEASESET_ENTRY_TYPE_LEASESET2)

	entry := MetaLeaseSetEntry{
		hash:       hash,
		leaseType:  leaseType,
		expires:    expires,
		cost:       cost,
		properties: common.Mapping{},
	}

	bytes, err := entry.Bytes()
	assert.NoError(t, err)

	// Verify size: hash(32) + type(1) + expires(4) + cost(1) + empty properties(2) = 40 bytes
	assert.Equal(t, 40, len(bytes))

	// Verify hash
	assert.Equal(t, hash[:], bytes[0:32])

	// Verify type
	assert.Equal(t, leaseType, bytes[32])

	// Verify expires
	parsedExpires := binary.BigEndian.Uint32(bytes[33:37])
	assert.Equal(t, expires, parsedExpires)

	// Verify cost
	assert.Equal(t, cost, bytes[37])

	// Verify empty properties (2 zero bytes)
	assert.Equal(t, byte(0x00), bytes[38])
	assert.Equal(t, byte(0x00), bytes[39])
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
	// dest(391) + published(4) + expires(2) + flags(2) + options(2) + numEntries(1) + 2*entry(40) + sig(64) = 546
	assert.GreaterOrEqual(t, len(bytes), 546)

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

// TestMetaLeaseSetBytesWithProperties tests serialization with non-empty properties
func TestMetaLeaseSetBytesWithProperties(t *testing.T) {
	dest := createTestDestinationStruct(t)
	published := uint32(time.Now().Unix())
	expires := uint16(600)

	// Create entry with properties
	hash := sha256.Sum256([]byte("test"))
	props, err := common.GoMapToMapping(map[string]string{"key": "value"})
	assert.NoError(t, err)

	entry := MetaLeaseSetEntry{
		hash:       hash,
		leaseType:  uint8(META_LEASESET_ENTRY_TYPE_LEASESET2),
		expires:    uint32(time.Now().Unix() + 3600),
		cost:       uint8(5),
		properties: *props,
	}

	mls := MetaLeaseSet{
		destination:      dest,
		published:        published,
		expires:          expires,
		flags:            0,
		offlineSignature: nil,
		options:          common.Mapping{},
		numEntries:       1,
		entries:          []MetaLeaseSetEntry{entry},
		signature:        createTestSignature(),
	}

	bytes, err := mls.Bytes()
	assert.NoError(t, err)
	assert.NotEmpty(t, bytes)

	// Verify properties were serialized (entry will be longer than 40 bytes)
	// dest(391) + published(4) + expires(2) + flags(2) + options(2) + numEntries(1) + entry(>40) + sig(64)
	assert.Greater(t, len(bytes), 506, "Entry with properties should make total size larger")
}
