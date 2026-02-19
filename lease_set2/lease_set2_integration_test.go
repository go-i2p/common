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

//
// Round-trip / serialization integration tests
//

func TestLeaseSet2Bytes(t *testing.T) {
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	_, _, err := destination.ReadDestination(destData)
	require.NoError(t, err)

	data := destData
	published := uint32(1735689600)
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

	optionsSize := uint16(0)
	optionsSizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(optionsSizeBytes, optionsSize)
	data = append(data, optionsSizeBytes...)

	numKeys := byte(1)
	data = append(data, numKeys)

	keyType := uint16(key_certificate.KEYCERT_CRYPTO_X25519)
	keyLen := uint16(32)
	keyTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyTypeBytes, keyType)
	data = append(data, keyTypeBytes...)
	keyLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLenBytes, keyLen)
	data = append(data, keyLenBytes...)
	keyData := make([]byte, 32)
	for i := 0; i < 32; i++ {
		keyData[i] = byte(i)
	}
	data = append(data, keyData...)

	numLeases := byte(1)
	data = append(data, numLeases)

	hash := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hash[i] = byte(0xAA)
	}
	data = append(data, hash...)
	tunnelID := uint32(12345)
	tunnelIDBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tunnelIDBytes, tunnelID)
	data = append(data, tunnelIDBytes...)
	endDate := uint32(1735690200)
	endDateBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(endDateBytes, endDate)
	data = append(data, endDateBytes...)

	signatureData := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	for i := 0; i < signature.EdDSA_SHA512_Ed25519_SIZE; i++ {
		signatureData[i] = byte(0xFF - i)
	}
	data = append(data, signatureData...)

	ls2, remainder, err := ReadLeaseSet2(data)
	require.NoError(t, err, "Failed to parse LeaseSet2")
	require.Empty(t, remainder, "Should consume all data")

	serialized, err := ls2.Bytes()
	require.NoError(t, err, "Failed to serialize LeaseSet2")
	assert.Greater(t, len(serialized), 0, "Serialized data should not be empty")

	ls2RoundTrip, remainder2, err2 := ReadLeaseSet2(serialized)
	require.NoError(t, err2, "Failed to parse serialized LeaseSet2")
	require.Empty(t, remainder2, "Should consume all serialized data")

	origDestBytes, err := ls2.Destination().Bytes()
	require.NoError(t, err)
	roundTripDestBytes, err := ls2RoundTrip.Destination().Bytes()
	require.NoError(t, err)
	assert.Equal(t, origDestBytes, roundTripDestBytes, "Destinations should match")
	assert.Equal(t, ls2.Published(), ls2RoundTrip.Published(), "Published timestamps should match")
	assert.Equal(t, ls2.Expires(), ls2RoundTrip.Expires(), "Expiration offsets should match")
	assert.Equal(t, ls2.Flags(), ls2RoundTrip.Flags(), "Flags should match")
	assert.Equal(t, ls2.EncryptionKeyCount(), ls2RoundTrip.EncryptionKeyCount(), "Encryption key counts should match")
	assert.Equal(t, ls2.LeaseCount(), ls2RoundTrip.LeaseCount(), "Lease counts should match")
	assert.Equal(t, ls2.Signature().Bytes(), ls2RoundTrip.Signature().Bytes(), "Signatures should match")
}

func TestBytesUsesDestinationAPI(t *testing.T) {
	data := buildMinimalLeaseSet2Data(t, key_certificate.KEYCERT_SIGN_ED25519, 1, 0)
	ls2, _, err := ReadLeaseSet2(data)
	require.NoError(t, err)

	bytes, err := ls2.Bytes()
	require.NoError(t, err)

	ls2RT, _, err := ReadLeaseSet2(bytes)
	require.NoError(t, err)

	origDest, _ := ls2.Destination().Bytes()
	rtDest, _ := ls2RT.Destination().Bytes()
	assert.Equal(t, origDest, rtDest)
}

//
// Offline signature integration tests
//

func TestReadLeaseSet2WithValidOfflineSignature(t *testing.T) {
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

	offlineExpires := uint32(time.Now().Unix() + 86400)
	offExpBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(offExpBytes, offlineExpires)
	data = append(data, offExpBytes...)

	transientSigType := uint16(key_certificate.KEYCERT_SIGN_ED25519)
	tSigTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(tSigTypeBytes, transientSigType)
	data = append(data, tSigTypeBytes...)

	transientPubKey := make([]byte, 32)
	for i := range transientPubKey {
		transientPubKey[i] = byte(0xBB)
	}
	data = append(data, transientPubKey...)

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
	lHash := make([]byte, 32)
	for i := range lHash {
		lHash[i] = byte(i)
	}
	data = append(data, 0x01)
	data = append(data, lHash...)
	tunnelID := make([]byte, 4)
	binary.BigEndian.PutUint32(tunnelID, 12345)
	data = append(data, tunnelID...)
	endDate := make([]byte, 4)
	binary.BigEndian.PutUint32(endDate, uint32(time.Now().Unix()+600))
	data = append(data, endDate...)

	// Signature (Ed25519)
	sigData := make([]byte, 64)
	for i := range sigData {
		sigData[i] = byte(0xDD)
	}
	data = append(data, sigData...)

	ls2, remainder, err := ReadLeaseSet2(data)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	assert.True(t, ls2.HasOfflineKeys())
	require.NotNil(t, ls2.OfflineSignature())
	assert.Equal(t, offlineExpires, ls2.OfflineSignature().Expires())
	assert.Equal(t, transientSigType, ls2.OfflineSignature().TransientSigType())
	assert.Equal(t, transientPubKey, ls2.OfflineSignature().TransientPublicKey())
	assert.Equal(t, 1, ls2.EncryptionKeyCount())
	assert.Equal(t, 1, ls2.LeaseCount())
}

func TestBytesRoundTripWithOfflineSignature(t *testing.T) {
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

	offExpBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(offExpBytes, uint32(time.Now().Unix()+86400))
	data = append(data, offExpBytes...)
	tSigTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(tSigTypeBytes, key_certificate.KEYCERT_SIGN_ED25519)
	data = append(data, tSigTypeBytes...)
	data = append(data, make([]byte, 32)...) // transient key
	data = append(data, make([]byte, 64)...) // offline sig

	data = append(data, 0x00, 0x00) // empty options

	data = append(data, 0x01) // encryption key
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

	data = append(data, make([]byte, 64)...) // signature

	ls2, _, err := ReadLeaseSet2(data)
	require.NoError(t, err)
	require.True(t, ls2.HasOfflineKeys())

	serialized, err := ls2.Bytes()
	require.NoError(t, err)

	ls2RT, remainder, err := ReadLeaseSet2(serialized)
	require.NoError(t, err)
	assert.Empty(t, remainder)

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

//
// Options mapping round-trip test
//

func TestRoundTripWithNonEmptyOptions(t *testing.T) {
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

	mappingContent := []byte{
		0x01, 'a', '=', 0x01, 'b', ';',
		0x01, 'c', '=', 0x01, 'd', ';',
	}
	mappingSize := make([]byte, 2)
	binary.BigEndian.PutUint16(mappingSize, uint16(len(mappingContent)))
	data = append(data, mappingSize...)
	data = append(data, mappingContent...)

	data = append(data, 0x01) // encryption key
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

	data = append(data, make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)...)

	ls2, remainder, err := ReadLeaseSet2(data)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	opts := ls2.Options()
	vals := opts.Values()
	assert.Equal(t, 2, len(vals), "Should have 2 option pairs")

	serialized, err := ls2.Bytes()
	require.NoError(t, err)

	ls2RT, remainder2, err := ReadLeaseSet2(serialized)
	require.NoError(t, err)
	assert.Empty(t, remainder2)

	rtVals := ls2RT.Options().Values()
	assert.Equal(t, len(vals), len(rtVals), "Options count should match after round-trip")
}

//
// Verify integration tests
//

func TestVerifyRejectsInvalidSignature(t *testing.T) {
	data := buildMinimalLeaseSet2Data(t, key_certificate.KEYCERT_SIGN_ED25519, 1, 0)
	ls2, _, err := ReadLeaseSet2(data)
	require.NoError(t, err)

	err = ls2.Verify()
	assert.Error(t, err, "Verify should reject invalid/garbage signature")
}

func TestVerifyDataConsistency(t *testing.T) {
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

	sigBytes := ls2.Signature().Bytes()
	contentBytes := fullBytes[:len(fullBytes)-len(sigBytes)]
	expectedPrefix := append([]byte{LEASESET2_DBSTORE_TYPE}, contentBytes...)

	signingData, err := serializeLeaseSet2ForSigning(
		ls2.Destination(), ls2.Published(), ls2.Expires(), ls2.Flags(),
		ls2.OfflineSignature(), ls2.Options(), ls2.EncryptionKeys(), ls2.Leases(),
	)
	require.NoError(t, err)

	assert.Equal(t, expectedPrefix, signingData,
		"serializeLeaseSet2ForSigning and Verify must use the same data format (0x03 prefix)")
}

//
// Constructor with offline signature integration test
//

func TestConstructorWithOfflineSignature(t *testing.T) {
	dest := createTestDest(t)
	l := createTestLease2(t, 0)
	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

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
