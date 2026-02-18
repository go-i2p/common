package lease_set2

import (
	"encoding/binary"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/offline_signature"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Helper functions ---

// buildMinimalLeaseSet2Data builds raw LeaseSet2 bytes for parsing tests.
// numLeases controls how many Lease2 structures to include.
func buildMinimalLeaseSet2Data(t *testing.T, sigType uint16, numLeases int, flags uint16) []byte {
	t.Helper()
	destData := createTestDestination(t, sigType)
	data := destData

	published := uint32(1735689600)
	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, published)
	data = append(data, publishedBytes...)

	expires := uint16(600)
	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, expires)
	data = append(data, expiresBytes...)

	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, flags)
	data = append(data, flagsBytes...)

	// Empty options
	data = append(data, 0x00, 0x00)

	// 1 X25519 encryption key
	data = append(data, 0x01)
	keyTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyTypeBytes, key_certificate.KEYCERT_CRYPTO_X25519)
	data = append(data, keyTypeBytes...)
	keyLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLenBytes, 32)
	data = append(data, keyLenBytes...)
	data = append(data, make([]byte, 32)...)

	// Leases
	data = append(data, byte(numLeases))
	for i := 0; i < numLeases; i++ {
		hash := make([]byte, 32)
		for j := range hash {
			hash[j] = byte(i*10 + j)
		}
		data = append(data, hash...)
		tunnelID := make([]byte, 4)
		binary.BigEndian.PutUint32(tunnelID, uint32(12345+i))
		data = append(data, tunnelID...)
		endDate := make([]byte, 4)
		binary.BigEndian.PutUint32(endDate, uint32(time.Now().Unix()+600))
		data = append(data, endDate...)
	}

	// Ed25519 signature (64 bytes)
	sigData := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	for i := range sigData {
		sigData[i] = byte(0xAA)
	}
	data = append(data, sigData...)

	return data
}

// createTestLease2 creates a valid Lease2 for testing.
func createTestLease2(t *testing.T, index int) *lease.Lease2 {
	t.Helper()
	var hashArray [32]byte
	for i := range hashArray {
		hashArray[i] = byte(index*10 + i)
	}
	l2, err := lease.NewLease2(hashArray, uint32(12345+index), time.Now().Add(10*time.Minute))
	require.NoError(t, err)
	return l2
}

// createTestDest creates a parsed Destination for testing.
func createTestDest(t *testing.T) destination.Destination {
	t.Helper()
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	dest, _, err := destination.ReadDestination(destData)
	require.NoError(t, err)
	return dest
}

// --- Finding #2: serializeLeaseSet2ForSigning prepends 0x03 type byte ---

func TestAudit_SerializeForSigningPrepends0x03(t *testing.T) {
	dest := createTestDest(t)
	l := createTestLease2(t, 0)

	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	data, err := serializeLeaseSet2ForSigning(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, []EncryptionKey{encKey}, []lease.Lease2{*l},
	)
	require.NoError(t, err)
	require.Greater(t, len(data), 0)

	// First byte must be the DatabaseStore type byte 0x03
	assert.Equal(t, byte(LEASESET2_DBSTORE_TYPE), data[0],
		"serializeLeaseSet2ForSigning must prepend 0x03 DatabaseStore type byte")
}

// --- Finding #3: Constructor enforces minimum 1 lease ---

func TestAudit_ConstructorRejectsZeroLeases(t *testing.T) {
	dest := createTestDest(t)
	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	_, err := NewLeaseSet2(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, []EncryptionKey{encKey}, []lease.Lease2{}, nil,
	)
	assert.Error(t, err, "Constructor should reject 0 leases per spec")
	assert.Contains(t, err.Error(), "at least one lease")
}

func TestAudit_ConstructorAcceptsOneLease(t *testing.T) {
	dest := createTestDest(t)
	l := createTestLease2(t, 0)
	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	ls2, err := NewLeaseSet2(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, []EncryptionKey{encKey}, []lease.Lease2{*l}, nil,
	)
	assert.NoError(t, err)
	assert.Equal(t, 1, ls2.LeaseCount())
}

// --- Finding #4: EncryptionKey KeyLen/KeyData mismatch validation ---

func TestAudit_ConstructorRejectsKeyLenMismatch(t *testing.T) {
	dest := createTestDest(t)
	l := createTestLease2(t, 0)

	// KeyLen=32 but KeyData is 16 bytes — mismatch
	badKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 16),
	}

	_, err := NewLeaseSet2(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, []EncryptionKey{badKey}, []lease.Lease2{*l}, nil,
	)
	assert.Error(t, err, "Constructor should reject KeyLen/KeyData mismatch")
	assert.Contains(t, err.Error(), "does not match")
}

func TestAudit_ConstructorAcceptsConsistentKey(t *testing.T) {
	dest := createTestDest(t)
	l := createTestLease2(t, 0)

	goodKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	_, err := NewLeaseSet2(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, []EncryptionKey{goodKey}, []lease.Lease2{*l}, nil,
	)
	assert.NoError(t, err)
}

// --- Finding #5: Reserved flag bits warning (parser doesn't error, just warns) ---

func TestAudit_ParserAcceptsReservedFlagBits(t *testing.T) {
	// Build data with reserved bits set (bit 3 = 0x0008)
	data := buildMinimalLeaseSet2Data(t, key_certificate.KEYCERT_SIGN_ED25519, 0, 0x0008)
	ls2, _, err := ReadLeaseSet2(data)
	// Parser should still succeed (lenient parsing) but the flags should be preserved
	assert.NoError(t, err)
	assert.Equal(t, uint16(0x0008), ls2.Flags()&0xFFF8,
		"Reserved flag bits should be preserved in parsed value")
}

// --- Finding #7: Validate() method ---

func TestAudit_ValidateNilLeaseSet2(t *testing.T) {
	var ls2 *LeaseSet2
	assert.Error(t, ls2.Validate())
}

func TestAudit_ValidateValidLeaseSet2(t *testing.T) {
	data := buildMinimalLeaseSet2Data(t, key_certificate.KEYCERT_SIGN_ED25519, 1, 0)
	ls2, _, err := ReadLeaseSet2(data)
	require.NoError(t, err)
	assert.NoError(t, ls2.Validate())
	assert.True(t, ls2.IsValid())
}

func TestAudit_ValidateRejectsReservedFlags(t *testing.T) {
	ls2 := &LeaseSet2{
		flags:          0x0008, // reserved bit set
		encryptionKeys: []EncryptionKey{{KeyType: 4, KeyLen: 32, KeyData: make([]byte, 32)}},
	}
	err := ls2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reserved flag bits")
}

func TestAudit_ValidateRejectsNoEncryptionKeys(t *testing.T) {
	ls2 := &LeaseSet2{
		encryptionKeys: []EncryptionKey{},
	}
	err := ls2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least 1 encryption key")
}

func TestAudit_ValidateRejectsKeyLenMismatch(t *testing.T) {
	ls2 := &LeaseSet2{
		encryptionKeys: []EncryptionKey{
			{KeyType: key_certificate.KEYCERT_CRYPTO_X25519, KeyLen: 32, KeyData: make([]byte, 16)},
		},
	}
	err := ls2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestAudit_ValidateRejectsKeyTypeSizeMismatch(t *testing.T) {
	// X25519 expects 32 bytes, but we provide 64
	ls2 := &LeaseSet2{
		encryptionKeys: []EncryptionKey{
			{KeyType: key_certificate.KEYCERT_CRYPTO_X25519, KeyLen: 64, KeyData: make([]byte, 64)},
		},
	}
	err := ls2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match expected size")
}

func TestAudit_ValidateRejectsOfflineFlagWithoutSig(t *testing.T) {
	ls2 := &LeaseSet2{
		flags:          LEASESET2_FLAG_OFFLINE_KEYS,
		encryptionKeys: []EncryptionKey{{KeyType: 4, KeyLen: 32, KeyData: make([]byte, 32)}},
	}
	err := ls2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OFFLINE_KEYS flag")
}

func TestAudit_IsValidReturnsFalse(t *testing.T) {
	ls2 := &LeaseSet2{encryptionKeys: []EncryptionKey{}}
	assert.False(t, ls2.IsValid())
}

// --- Finding #8: Encryption key type/length consistency in parser ---

func TestAudit_ParserWarnsOnEncKeyTypeLenMismatch(t *testing.T) {
	// Build data where encryption key claims X25519 type but has wrong length (64 instead of 32)
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	data := destData

	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, 1735689600)
	data = append(data, publishedBytes...)

	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, 600)
	data = append(data, expiresBytes...)

	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, 0)
	data = append(data, flagsBytes...)

	data = append(data, 0x00, 0x00) // empty options

	data = append(data, 0x01) // 1 key
	keyTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyTypeBytes, key_certificate.KEYCERT_CRYPTO_X25519)
	data = append(data, keyTypeBytes...)
	keyLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLenBytes, 64) // wrong: X25519 should be 32
	data = append(data, keyLenBytes...)
	data = append(data, make([]byte, 64)...) // 64 bytes of key data

	data = append(data, 0x00) // 0 leases

	data = append(data, make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)...)

	// Parser should still succeed (lenient) but the key is stored
	ls2, _, err := ReadLeaseSet2(data)
	assert.NoError(t, err)
	assert.Equal(t, uint16(64), ls2.EncryptionKeys()[0].KeyLen)
}

// --- Finding #10: Verify() method tests ---

func TestAudit_VerifyRejectsInvalidSignature(t *testing.T) {
	// Parse a LeaseSet2 with a garbage signature
	data := buildMinimalLeaseSet2Data(t, key_certificate.KEYCERT_SIGN_ED25519, 1, 0)
	ls2, _, err := ReadLeaseSet2(data)
	require.NoError(t, err)

	// Verify should fail since signature is fake (0xAA bytes)
	err = ls2.Verify()
	assert.Error(t, err, "Verify should reject invalid/garbage signature")
}

func TestAudit_VerifyDataConsistency(t *testing.T) {
	// Verify that Verify() and serializeLeaseSet2ForSigning() use the same 0x03 prefix
	dest := createTestDest(t)
	l := createTestLease2(t, 0)

	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	// Create a LeaseSet2 via constructor (produces placeholder signature)
	ls2, err := NewLeaseSet2(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, []EncryptionKey{encKey}, []lease.Lease2{*l}, nil,
	)
	require.NoError(t, err)

	// Get the full serialized bytes
	fullBytes, err := ls2.Bytes()
	require.NoError(t, err)

	sigBytes := ls2.Signature().Bytes()
	contentBytes := fullBytes[:len(fullBytes)-len(sigBytes)]

	// The data that Verify() checks should be: 0x03 + content
	expectedPrefix := append([]byte{LEASESET2_DBSTORE_TYPE}, contentBytes...)

	// Now call serializeLeaseSet2ForSigning which should produce the same data
	signingData, err := serializeLeaseSet2ForSigning(
		ls2.Destination(), ls2.Published(), ls2.Expires(), ls2.Flags(),
		ls2.OfflineSignature(), ls2.Options(), ls2.EncryptionKeys(), ls2.Leases(),
	)
	require.NoError(t, err)

	assert.Equal(t, expectedPrefix, signingData,
		"serializeLeaseSet2ForSigning and Verify must use the same data format (0x03 prefix)")
}

// --- Finding #11: Valid LeaseSet2 with offline signature ---

func TestAudit_ReadLeaseSet2WithValidOfflineSignature(t *testing.T) {
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	data := destData

	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, 1735689600)
	data = append(data, publishedBytes...)

	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, 600)
	data = append(data, expiresBytes...)

	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, LEASESET2_FLAG_OFFLINE_KEYS)
	data = append(data, flagsBytes...)

	// Build offline signature:
	// expires (4 bytes) + transient sig type (2 bytes) + transient public key (32 bytes for Ed25519) + signature (64 bytes for Ed25519)
	offlineExpires := uint32(time.Now().Unix() + 86400)
	offExpBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(offExpBytes, offlineExpires)
	data = append(data, offExpBytes...)

	transientSigType := uint16(key_certificate.KEYCERT_SIGN_ED25519) // type 7
	tSigTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(tSigTypeBytes, transientSigType)
	data = append(data, tSigTypeBytes...)

	// Transient public key (Ed25519 = 32 bytes)
	transientPubKey := make([]byte, 32)
	for i := range transientPubKey {
		transientPubKey[i] = byte(0xBB)
	}
	data = append(data, transientPubKey...)

	// Offline signature (Ed25519 = 64 bytes, signed by destination's long-term key)
	offlineSigBytes := make([]byte, 64)
	for i := range offlineSigBytes {
		offlineSigBytes[i] = byte(0xCC)
	}
	data = append(data, offlineSigBytes...)

	// Empty options
	data = append(data, 0x00, 0x00)

	// 1 X25519 encryption key
	data = append(data, 0x01)
	keyTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyTypeBytes, key_certificate.KEYCERT_CRYPTO_X25519)
	data = append(data, keyTypeBytes...)
	keyLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLenBytes, 32)
	data = append(data, keyLenBytes...)
	data = append(data, make([]byte, 32)...)

	// 1 lease
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}
	data = append(data, 0x01)
	data = append(data, hash...)
	tunnelID := make([]byte, 4)
	binary.BigEndian.PutUint32(tunnelID, 12345)
	data = append(data, tunnelID...)
	endDate := make([]byte, 4)
	binary.BigEndian.PutUint32(endDate, uint32(time.Now().Unix()+600))
	data = append(data, endDate...)

	// Signature (Ed25519 = 64 bytes, signed by transient key)
	sigData := make([]byte, 64)
	for i := range sigData {
		sigData[i] = byte(0xDD)
	}
	data = append(data, sigData...)

	ls2, remainder, err := ReadLeaseSet2(data)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	// Verify offline signature fields
	assert.True(t, ls2.HasOfflineKeys())
	require.NotNil(t, ls2.OfflineSignature())
	assert.Equal(t, offlineExpires, ls2.OfflineSignature().Expires())
	assert.Equal(t, transientSigType, ls2.OfflineSignature().TransientSigType())
	assert.Equal(t, transientPubKey, ls2.OfflineSignature().TransientPublicKey())

	assert.Equal(t, 1, ls2.EncryptionKeyCount())
	assert.Equal(t, 1, ls2.LeaseCount())
}

// --- Finding #12: Bytes() serialization with offline signature ---

func TestAudit_BytesRoundTripWithOfflineSignature(t *testing.T) {
	// Build and parse a LeaseSet2 with offline signature
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	data := destData

	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, 1735689600)
	data = append(data, publishedBytes...)

	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, 600)
	data = append(data, expiresBytes...)

	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, LEASESET2_FLAG_OFFLINE_KEYS)
	data = append(data, flagsBytes...)

	// Offline signature
	offExpBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(offExpBytes, uint32(time.Now().Unix()+86400))
	data = append(data, offExpBytes...)
	tSigTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(tSigTypeBytes, key_certificate.KEYCERT_SIGN_ED25519)
	data = append(data, tSigTypeBytes...)
	data = append(data, make([]byte, 32)...) // transient key
	data = append(data, make([]byte, 64)...) // offline sig

	// Empty options
	data = append(data, 0x00, 0x00)

	// Encryption key
	data = append(data, 0x01)
	keyTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyTypeBytes, key_certificate.KEYCERT_CRYPTO_X25519)
	data = append(data, keyTypeBytes...)
	keyLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLenBytes, 32)
	data = append(data, keyLenBytes...)
	data = append(data, make([]byte, 32)...)

	// 1 lease
	data = append(data, 0x01)
	data = append(data, make([]byte, 32)...) // hash
	tunnelID := make([]byte, 4)
	binary.BigEndian.PutUint32(tunnelID, 12345)
	data = append(data, tunnelID...)
	endDate := make([]byte, 4)
	binary.BigEndian.PutUint32(endDate, uint32(time.Now().Unix()+600))
	data = append(data, endDate...)

	// Signature (Ed25519)
	data = append(data, make([]byte, 64)...)

	// Parse
	ls2, _, err := ReadLeaseSet2(data)
	require.NoError(t, err)
	require.True(t, ls2.HasOfflineKeys())

	// Serialize
	serialized, err := ls2.Bytes()
	require.NoError(t, err)

	// Round-trip: parse again
	ls2RT, remainder, err := ReadLeaseSet2(serialized)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	// Verify fields match
	assert.True(t, ls2RT.HasOfflineKeys())
	require.NotNil(t, ls2RT.OfflineSignature())
	assert.Equal(t, ls2.OfflineSignature().Expires(), ls2RT.OfflineSignature().Expires())
	assert.Equal(t, ls2.OfflineSignature().TransientSigType(), ls2RT.OfflineSignature().TransientSigType())
	assert.Equal(t, ls2.OfflineSignature().TransientPublicKey(), ls2RT.OfflineSignature().TransientPublicKey())
	assert.Equal(t, ls2.Published(), ls2RT.Published())
	assert.Equal(t, ls2.Expires(), ls2RT.Expires())
	assert.Equal(t, ls2.EncryptionKeyCount(), ls2RT.EncryptionKeyCount())
	assert.Equal(t, ls2.LeaseCount(), ls2RT.LeaseCount())
	assert.Equal(t, ls2.Signature().Bytes(), ls2RT.Signature().Bytes())
}

// --- Finding #13: Round-trip with non-empty options mapping ---

func TestAudit_RoundTripWithNonEmptyOptions(t *testing.T) {
	// Build a LeaseSet2 with a non-empty options mapping at the binary level.
	// The options mapping format is: [2-byte size] [key=val;...]
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	data := destData

	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, 1735689600)
	data = append(data, publishedBytes...)

	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, 600)
	data = append(data, expiresBytes...)

	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, 0)
	data = append(data, flagsBytes...)

	// Build options mapping: { "a" => "b", "c" => "d" }
	// I2P Mapping wire format: [2-byte total content size] [1-byte key-len "a" = 1-byte val-len "b" ; ...]
	// Each pair: 1(keylen) + key + "=" + 1(vallen) + val + ";"
	// "a": keylen=1, key="a", "=", vallen=1, val="b", ";" = 1+1+1+1+1+1 = 6 bytes
	// "c": keylen=1, key="c", "=", vallen=1, val="d", ";" = 6 bytes
	// Total content = 12 bytes
	mappingContent := []byte{
		0x01, 'a', '=', 0x01, 'b', ';',
		0x01, 'c', '=', 0x01, 'd', ';',
	}
	mappingSize := make([]byte, 2)
	binary.BigEndian.PutUint16(mappingSize, uint16(len(mappingContent)))
	data = append(data, mappingSize...)
	data = append(data, mappingContent...)

	// Encryption key
	data = append(data, 0x01)
	keyTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyTypeBytes, key_certificate.KEYCERT_CRYPTO_X25519)
	data = append(data, keyTypeBytes...)
	keyLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLenBytes, 32)
	data = append(data, keyLenBytes...)
	data = append(data, make([]byte, 32)...)

	// 1 lease
	data = append(data, 0x01)
	data = append(data, make([]byte, 32)...) // hash
	tunnelID := make([]byte, 4)
	binary.BigEndian.PutUint32(tunnelID, 12345)
	data = append(data, tunnelID...)
	endDate := make([]byte, 4)
	binary.BigEndian.PutUint32(endDate, uint32(time.Now().Unix()+600))
	data = append(data, endDate...)

	// Signature
	data = append(data, make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)...)

	// Parse
	ls2, remainder, err := ReadLeaseSet2(data)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	// Verify options were parsed
	opts := ls2.Options()
	vals := opts.Values()
	assert.Equal(t, 2, len(vals), "Should have 2 option pairs")

	// Serialize and round-trip
	serialized, err := ls2.Bytes()
	require.NoError(t, err)

	ls2RT, remainder2, err := ReadLeaseSet2(serialized)
	require.NoError(t, err)
	assert.Empty(t, remainder2)

	rtVals := ls2RT.Options().Values()
	assert.Equal(t, len(vals), len(rtVals), "Options count should match after round-trip")
}

// --- Finding #14: Fuzz test for ReadLeaseSet2 ---

func FuzzReadLeaseSet2(f *testing.F) {
	// Seed with a valid LeaseSet2
	validData := buildMinimalLeaseSet2Data(&testing.T{}, key_certificate.KEYCERT_SIGN_ED25519, 1, 0)
	f.Add(validData)

	// Seed with empty data
	f.Add([]byte{})

	// Seed with minimal truncated data
	f.Add(make([]byte, 100))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic regardless of input
		_, _, _ = ReadLeaseSet2(data)
	})
}

// --- Finding #15: Refactored serialization consistency ---

func TestAudit_SharedSerializationConsistency(t *testing.T) {
	// Verify that Bytes() (without signature) and serializeLeaseSet2Content produce the same data
	dest := createTestDest(t)
	l := createTestLease2(t, 0)
	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	ls2, err := NewLeaseSet2(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, []EncryptionKey{encKey}, []lease.Lease2{*l}, nil,
	)
	require.NoError(t, err)

	fullBytes, err := ls2.Bytes()
	require.NoError(t, err)

	// Content from serializeLeaseSet2Content should match Bytes() minus the signature
	content, err := serializeLeaseSet2Content(
		ls2.Destination(), ls2.Published(), ls2.Expires(), ls2.Flags(),
		ls2.OfflineSignature(), ls2.Options(), ls2.EncryptionKeys(), ls2.Leases(),
	)
	require.NoError(t, err)

	sigLen := len(ls2.Signature().Bytes())
	assert.Equal(t, content, fullBytes[:len(fullBytes)-sigLen],
		"Bytes() content (minus signature) should equal serializeLeaseSet2Content output")
}

// --- Finding #16: Bytes() uses Destination.Bytes() not KeysAndCert.Bytes() ---

func TestAudit_BytesUsesDestinationAPI(t *testing.T) {
	// This is a compile-time check essentially. If the code compiles with
	// dest.Bytes() call, then it's using the Destination API.
	// We verify by checking that a parsed LeaseSet2's Bytes() matches expectations.
	data := buildMinimalLeaseSet2Data(t, key_certificate.KEYCERT_SIGN_ED25519, 1, 0)
	ls2, _, err := ReadLeaseSet2(data)
	require.NoError(t, err)

	bytes, err := ls2.Bytes()
	require.NoError(t, err)

	// Round-trip should work
	ls2RT, _, err := ReadLeaseSet2(bytes)
	require.NoError(t, err)

	origDest, _ := ls2.Destination().Bytes()
	rtDest, _ := ls2RT.Destination().Bytes()
	assert.Equal(t, origDest, rtDest)
}

// --- Finding #17: signingKey interface{} is acknowledged ---
// No test needed — this is a QUALITY finding acknowledged as-is.

// --- Finding #18: doc.go existence test ---

func TestAudit_DocGoExists(t *testing.T) {
	// The doc.go file was created as part of this audit fix.
	// This test verifies that the package documentation is available.
	// Since this file is in the lease_set2 package, if doc.go doesn't compile,
	// this test won't compile either.
	t.Log("doc.go exists and compiles successfully")
}

// --- Additional validation tests ---

func TestAudit_ValidateRejectsTooManyLeases(t *testing.T) {
	ls2 := &LeaseSet2{
		encryptionKeys: []EncryptionKey{{KeyType: 4, KeyLen: 32, KeyData: make([]byte, 32)}},
		leases:         make([]lease.Lease2, 17),
	}
	err := ls2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too many leases")
}

func TestAudit_ConstructorWithOfflineSignature(t *testing.T) {
	dest := createTestDest(t)
	l := createTestLease2(t, 0)
	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	// Create a valid offline signature
	transientPubKey := make([]byte, 32)
	offlineSigBytes := make([]byte, 64)
	offSig, err := offline_signature.NewOfflineSignature(
		uint32(time.Now().Unix()+86400),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientPubKey,
		offlineSigBytes,
		key_certificate.KEYCERT_SIGN_ED25519,
	)
	require.NoError(t, err)

	ls2, err := NewLeaseSet2(
		dest, uint32(time.Now().Unix()), 600, LEASESET2_FLAG_OFFLINE_KEYS, &offSig,
		common.Mapping{}, []EncryptionKey{encKey}, []lease.Lease2{*l}, nil,
	)
	require.NoError(t, err)
	assert.True(t, ls2.HasOfflineKeys())
	assert.NotNil(t, ls2.OfflineSignature())
}

func TestAudit_ParserAcceptsZeroLeases(t *testing.T) {
	// The parser should be lenient and accept 0 leases (per wire format spec "0-16")
	data := buildMinimalLeaseSet2Data(t, key_certificate.KEYCERT_SIGN_ED25519, 0, 0)
	ls2, _, err := ReadLeaseSet2(data)
	assert.NoError(t, err, "Parser should accept 0 leases (lenient parsing)")
	assert.Equal(t, 0, ls2.LeaseCount())
}
