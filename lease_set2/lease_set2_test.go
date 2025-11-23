package lease_set2

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestDestination creates a minimal valid destination for testing
func createTestDestination(t *testing.T, sigType uint16) []byte {
	t.Helper()
	// Create 384 bytes of keys data (ElGamal 256 + padding 128)
	keysData := make([]byte, 384)
	for i := range keysData {
		keysData[i] = byte(i % 256)
	}

	// Create KEY certificate (type=5) with 4-byte payload
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
	assert.Equal(t, dest.Base32Address(), ls2.Destination().Base32Address())
}

func TestReadLeaseSet2TooShort(t *testing.T) {
	data := make([]byte, 100)
	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

func TestReadLeaseSet2InvalidEncryptionKeyCount(t *testing.T) {
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

	numKeys := byte(0)
	data = append(data, numKeys)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
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

func TestReadLeaseSet2TooManyEncryptionKeys(t *testing.T) {
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

	numKeys := byte(17)
	data = append(data, numKeys)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

func TestReadLeaseSet2TooManyLeases(t *testing.T) {
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

	numLeases := byte(17)
	data = append(data, numLeases)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

func TestReadLeaseSet2WithOfflineKeys(t *testing.T) {
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

	flags := uint16(LEASESET2_FLAG_OFFLINE_KEYS)
	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, flags)
	data = append(data, flagsBytes...)

	// Truncated offline signature
	data = append(data, []byte{0x00, 0x00, 0x00}...)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

func TestReadLeaseSet2InvalidEncryptionKeyData(t *testing.T) {
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

	keyData := make([]byte, 10)
	data = append(data, keyData...)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

func TestReadLeaseSet2InvalidLeaseData(t *testing.T) {
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

	numLeases := byte(1)
	data = append(data, numLeases)

	truncatedLease := make([]byte, 20)
	data = append(data, truncatedLease...)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

func TestReadLeaseSet2InvalidSignature(t *testing.T) {
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

	numLeases := byte(0)
	data = append(data, numLeases)

	truncatedSig := make([]byte, 20)
	data = append(data, truncatedSig...)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}
