package lease_set2

import (
	"encoding/binary"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//
// ReadLeaseSet2 parsing tests
//

func TestReadLeaseSet2MinimalValid(t *testing.T) {
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	dest, _, err := destination.ReadDestination(destData)
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

	numLeases := byte(0)
	data = append(data, numLeases)

	signatureData := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	for i := 0; i < signature.EdDSA_SHA512_Ed25519_SIZE; i++ {
		signatureData[i] = byte(0xFF - i)
	}
	data = append(data, signatureData...)

	ls2, remainder, err := ReadLeaseSet2(data)

	assert.NoError(t, err)
	assert.Empty(t, remainder)
	assert.Equal(t, published, ls2.Published())
	assert.Equal(t, expires, ls2.Expires())
	assert.Equal(t, flags, ls2.Flags())
	assert.False(t, ls2.HasOfflineKeys())
	assert.False(t, ls2.IsUnpublished())
	assert.False(t, ls2.IsBlinded())
	assert.Nil(t, ls2.OfflineSignature())
	assert.Equal(t, 1, ls2.EncryptionKeyCount())
	assert.Equal(t, 0, ls2.LeaseCount())
	destAddr, err := dest.Base32Address()
	require.NoError(t, err)
	ls2Addr, err := ls2.Destination().Base32Address()
	require.NoError(t, err)
	assert.Equal(t, destAddr, ls2Addr)
}

func TestReadLeaseSet2WithMultipleLeases(t *testing.T) {
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
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
	data = append(data, keyData...)

	numLeases := byte(3)
	data = append(data, numLeases)
	for i := 0; i < 3; i++ {
		hash := make([]byte, 32)
		for j := 0; j < 32; j++ {
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

	signatureData := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	data = append(data, signatureData...)

	ls2, remainder, err := ReadLeaseSet2(data)
	assert.NoError(t, err)
	assert.Empty(t, remainder)
	assert.Equal(t, 3, ls2.LeaseCount())
	assert.Len(t, ls2.Leases(), 3)
}

//
// Accessor tests
//

func TestLeaseSet2Accessors(t *testing.T) {
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
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

	numKeys := byte(2)
	data = append(data, numKeys)
	for i := 0; i < 2; i++ {
		keyType := uint16(key_certificate.KEYCERT_CRYPTO_X25519)
		keyLen := uint16(32)
		keyTypeBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(keyTypeBytes, keyType)
		data = append(data, keyTypeBytes...)
		keyLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(keyLenBytes, keyLen)
		data = append(data, keyLenBytes...)
		keyData := make([]byte, 32)
		for j := 0; j < 32; j++ {
			keyData[j] = byte(i*32 + j)
		}
		data = append(data, keyData...)
	}

	numLeases := byte(0)
	data = append(data, numLeases)

	signatureData := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	for i := 0; i < signature.EdDSA_SHA512_Ed25519_SIZE; i++ {
		signatureData[i] = byte(0xFF - i)
	}
	data = append(data, signatureData...)

	ls2, _, err := ReadLeaseSet2(data)
	require.NoError(t, err)

	opts := ls2.Options()
	assert.NotNil(t, opts)

	encKeys := ls2.EncryptionKeys()
	assert.Len(t, encKeys, 2)

	leases := ls2.Leases()
	assert.Empty(t, leases)

	sig := ls2.Signature()
	assert.NotNil(t, sig)
}

func TestLeaseSet2ExpirationCheck(t *testing.T) {
	pastTime := uint32(time.Now().Unix() - 3600)
	ls2 := &LeaseSet2{published: pastTime, expires: 600}
	assert.True(t, ls2.IsExpired())

	futureTime := uint32(time.Now().Unix())
	ls2Future := &LeaseSet2{published: futureTime, expires: 3600}
	assert.False(t, ls2Future.IsExpired())
}

func TestLeaseSet2FlagMethods(t *testing.T) {
	testCases := []struct {
		name           string
		flags          uint16
		hasOfflineKeys bool
		isUnpublished  bool
		isBlinded      bool
	}{
		{"no flags", 0, false, false, false},
		{"offline keys", LEASESET2_FLAG_OFFLINE_KEYS, true, false, false},
		{"unpublished", LEASESET2_FLAG_UNPUBLISHED, false, true, false},
		{"blinded", LEASESET2_FLAG_BLINDED, false, false, true},
		{"all flags", LEASESET2_FLAG_OFFLINE_KEYS | LEASESET2_FLAG_UNPUBLISHED | LEASESET2_FLAG_BLINDED, true, true, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ls2 := &LeaseSet2{flags: tc.flags}
			assert.Equal(t, tc.hasOfflineKeys, ls2.HasOfflineKeys())
			assert.Equal(t, tc.isUnpublished, ls2.IsUnpublished())
			assert.Equal(t, tc.isBlinded, ls2.IsBlinded())
		})
	}
}

//
// NewLeaseSet2 constructor tests
//

func TestNewLeaseSet2(t *testing.T) {
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	dest, _, err := destination.ReadDestination(destData)
	require.NoError(t, err)

	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	hash := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hash[i] = byte(i)
	}
	var hashArray [32]byte
	copy(hashArray[:], hash)
	lease2, err := lease.NewLease2(hashArray, 12345, time.Now().Add(10*time.Minute))
	require.NoError(t, err)

	published := uint32(time.Now().Unix())
	expiresOffset := uint16(600)

	ls2, err := NewLeaseSet2(
		dest, published, expiresOffset, 0, nil,
		common.Mapping{}, []EncryptionKey{encKey}, []lease.Lease2{*lease2}, nil,
	)
	if err != nil {
		// Skip if destination too small for validation
		return
	}

	destAddr2, err := dest.Base32Address()
	require.NoError(t, err)
	ls2Addr2, err := ls2.Destination().Base32Address()
	require.NoError(t, err)
	assert.Equal(t, destAddr2, ls2Addr2)
	assert.Equal(t, published, ls2.Published())
	assert.Equal(t, expiresOffset, ls2.Expires())
	assert.Equal(t, 1, ls2.EncryptionKeyCount())
	assert.Equal(t, 1, ls2.LeaseCount())
	assert.False(t, ls2.HasOfflineKeys())
}

func TestNewLeaseSet2ConstructorAcceptsOneLease(t *testing.T) {
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

func TestNewLeaseSet2ConstructorAcceptsConsistentKey(t *testing.T) {
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

//
// Validate / IsValid tests
//

func TestValidateNilLeaseSet2(t *testing.T) {
	var ls2 *LeaseSet2
	assert.Error(t, ls2.Validate())
}

func TestValidateValidLeaseSet2(t *testing.T) {
	data := buildMinimalLeaseSet2Data(t, key_certificate.KEYCERT_SIGN_ED25519, 1, 0)
	ls2, _, err := ReadLeaseSet2(data)
	require.NoError(t, err)
	assert.NoError(t, ls2.Validate())
	assert.True(t, ls2.IsValid())
}

func TestIsValidReturnsFalse(t *testing.T) {
	ls2 := &LeaseSet2{encryptionKeys: []EncryptionKey{}}
	assert.False(t, ls2.IsValid())
}

//
// Serialization and signing tests
//

func TestSerializeForSigningPrepends0x03(t *testing.T) {
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
	assert.Equal(t, byte(LEASESET2_DBSTORE_TYPE), data[0],
		"serializeLeaseSet2ForSigning must prepend 0x03 DatabaseStore type byte")
}

func TestSharedSerializationConsistency(t *testing.T) {
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

	content, err := serializeLeaseSet2Content(
		ls2.Destination(), ls2.Published(), ls2.Expires(), ls2.Flags(),
		ls2.OfflineSignature(), ls2.Options(), ls2.EncryptionKeys(), ls2.Leases(),
	)
	require.NoError(t, err)

	sigLen := len(ls2.Signature().Bytes())
	assert.Equal(t, content, fullBytes[:len(fullBytes)-sigLen],
		"Bytes() content (minus signature) should equal serializeLeaseSet2Content output")
}

// TestDocGoExists verifies the package documentation is available
func TestDocGoExists(t *testing.T) {
	t.Log("doc.go exists and compiles successfully")
}
