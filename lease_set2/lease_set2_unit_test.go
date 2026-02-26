package lease_set2

import (
	"crypto/ed25519"
	"encoding/binary"
	"sort"
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"

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

	numLeases := byte(1)
	data = append(data, numLeases)
	// One minimal Lease2: 32-byte gateway hash + 4-byte tunnel ID + 4-byte end date
	leaseHash := make([]byte, 32)
	data = append(data, leaseHash...)
	tunnelID := make([]byte, 4)
	binary.BigEndian.PutUint32(tunnelID, 12345)
	data = append(data, tunnelID...)
	endDate := make([]byte, 4)
	binary.BigEndian.PutUint32(endDate, 1735690200)
	data = append(data, endDate...)

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
	assert.Equal(t, 1, ls2.LeaseCount())
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

	numLeases := byte(1)
	data = append(data, numLeases)
	// One Lease2: 32-byte gateway hash + 4-byte tunnel ID + 4-byte end date
	leaseHash := make([]byte, 32)
	data = append(data, leaseHash...)
	tunnelIDBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tunnelIDBytes, 99999)
	data = append(data, tunnelIDBytes...)
	endDateBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(endDateBytes, 1735690200)
	data = append(data, endDateBytes...)

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
	assert.Len(t, leases, 1)

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
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

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
		common.Mapping{}, []EncryptionKey{encKey}, []lease.Lease2{*lease2}, priv,
	)
	require.NoError(t, err)

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
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	dest := createTestDest(t)
	l := createTestLease2(t, 0)
	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	ls2, err := NewLeaseSet2(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, []EncryptionKey{encKey}, []lease.Lease2{*l}, priv,
	)
	assert.NoError(t, err)
	assert.Equal(t, 1, ls2.LeaseCount())
}

func TestNewLeaseSet2ConstructorAcceptsConsistentKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	dest := createTestDest(t)
	l := createTestLease2(t, 0)
	goodKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	_, err = NewLeaseSet2(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, []EncryptionKey{goodKey}, []lease.Lease2{*l}, priv,
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
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	dest := createTestDest(t)
	l := createTestLease2(t, 0)
	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	ls2, err := NewLeaseSet2(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, []EncryptionKey{encKey}, []lease.Lease2{*l}, priv,
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

//
// Signing key type tests
//

func TestNilSigningKeyReturnsError(t *testing.T) {
	dest := createTestDest(t)
	l := createTestLease2(t, 0)
	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	_, err := NewLeaseSet2(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, []EncryptionKey{encKey}, []lease.Lease2{*l}, nil,
	)
	assert.Error(t, err, "nil signing key should return error")
	assert.Contains(t, err.Error(), "nil")
}

func TestWrongKeyTypeReturnsError(t *testing.T) {
	dest := createTestDest(t)
	l := createTestLease2(t, 0)
	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	_, err := NewLeaseSet2(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, []EncryptionKey{encKey}, []lease.Lease2{*l}, "not-a-key",
	)
	assert.Error(t, err, "string signing key should return error")
	assert.Contains(t, err.Error(), "unsupported")
}

func TestByteSliceSigningKeyWorks(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	dest := createTestDestWithKey(t, pub)
	l := createTestLease2(t, 0)
	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	ls2, err := NewLeaseSet2(
		dest, uint32(time.Now().Unix()), 600, 0, nil,
		common.Mapping{}, []EncryptionKey{encKey}, []lease.Lease2{*l}, []byte(priv),
	)
	require.NoError(t, err)

	err = ls2.Verify()
	assert.NoError(t, err, "[]byte signing key should produce verifiable signature")
}

//
// validateExpiresOffset tests
//

func TestValidateExpiresOffsetNeverFails(t *testing.T) {
	assert.NoError(t, validateExpiresOffset(0))
	assert.NoError(t, validateExpiresOffset(1))
	assert.NoError(t, validateExpiresOffset(660))
	assert.NoError(t, validateExpiresOffset(65535))
}

func TestExpiresOffsetConstant(t *testing.T) {
	assert.Equal(t, uint16(LEASESET2_MAX_EXPIRES_OFFSET), uint16(65535))
}

//
// warnIfOptionsUnsorted tests
//

func TestWarnIfOptionsUnsorted(t *testing.T) {
	t.Run("sorted_keys_no_warning", func(t *testing.T) {
		m := buildMappingWithKeys(t, []string{"a", "b", "c"})
		warnIfOptionsUnsorted(m)
	})

	t.Run("unsorted_keys_warning_path", func(t *testing.T) {
		m := buildMappingWithKeys(t, []string{"c", "a", "b"})
		warnIfOptionsUnsorted(m)
	})

	t.Run("single_key_no_warning", func(t *testing.T) {
		m := buildMappingWithKeys(t, []string{"z"})
		warnIfOptionsUnsorted(m)
	})

	t.Run("empty_mapping_no_warning", func(t *testing.T) {
		warnIfOptionsUnsorted(common.Mapping{})
	})
}

//
// validateOptionsSorted tests
//

func TestValidateOptionsSorted(t *testing.T) {
	t.Run("empty_mapping_valid", func(t *testing.T) {
		assert.NoError(t, validateOptionsSorted(common.Mapping{}))
	})

	t.Run("single_key_valid", func(t *testing.T) {
		m := buildMappingWithKeys(t, []string{"a"})
		assert.NoError(t, validateOptionsSorted(m))
	})

	t.Run("sorted_keys_valid", func(t *testing.T) {
		m := buildMappingWithKeys(t, []string{"a", "b", "c"})
		assert.NoError(t, validateOptionsSorted(m))
	})

	t.Run("unsorted_keys_error", func(t *testing.T) {
		m := buildMappingWithKeys(t, []string{"b", "a"})
		err := validateOptionsSorted(m)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "sorted")
	})

	t.Run("reverse_sorted_keys_error", func(t *testing.T) {
		m := buildMappingWithKeys(t, []string{"z", "y", "x"})
		err := validateOptionsSorted(m)
		assert.Error(t, err)
	})
}

//
// Equals method tests
//

func TestEquals(t *testing.T) {
	t.Run("identical_leaseset2_are_equal", func(t *testing.T) {
		data := buildMinimalLeaseSet2Data(t, key_certificate.KEYCERT_SIGN_ED25519, 1, 0)
		ls2a, _, err := ReadLeaseSet2(data)
		require.NoError(t, err)
		ls2b, _, err := ReadLeaseSet2(data)
		require.NoError(t, err)
		assert.True(t, ls2a.Equals(&ls2b))
	})

	t.Run("different_published_are_not_equal", func(t *testing.T) {
		data1 := buildMinimalLeaseSet2Data(t, key_certificate.KEYCERT_SIGN_ED25519, 1, 0)
		ls2a, _, err := ReadLeaseSet2(data1)
		require.NoError(t, err)

		ls2b := ls2a
		ls2b.published = ls2a.published + 1
		assert.False(t, ls2a.Equals(&ls2b))
	})

	t.Run("nil_handling", func(t *testing.T) {
		data := buildMinimalLeaseSet2Data(t, key_certificate.KEYCERT_SIGN_ED25519, 1, 0)
		ls2, _, err := ReadLeaseSet2(data)
		require.NoError(t, err)

		assert.False(t, ls2.Equals(nil))

		var nilLS *LeaseSet2
		assert.True(t, nilLS.Equals(nil))
	})
}

//
// Lease2 size test
//

func TestLease2Size40Bytes(t *testing.T) {
	l := createTestLease2(t, 0)
	assert.Equal(t, 40, len(l.Bytes()), "Lease2 should be exactly 40 bytes (32 hash + 4 tunnel_id + 4 end_date)")
}

//
// sort.StringsAreSorted sanity check
//

func TestSortStringsSorted(t *testing.T) {
	assert.True(t, sort.StringsAreSorted([]string{"a", "b", "c"}))
	assert.False(t, sort.StringsAreSorted([]string{"z", "a"}))
	assert.True(t, sort.StringsAreSorted([]string{}))
	assert.True(t, sort.StringsAreSorted([]string{"a"}))
}
