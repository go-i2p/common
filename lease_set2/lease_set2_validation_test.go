package lease_set2

import (
	"encoding/binary"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/offline_signature"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//
// ReadLeaseSet2 input validation tests
//

func TestReadLeaseSet2TooShort(t *testing.T) {
	data := make([]byte, 100)
	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

func TestReadLeaseSet2InvalidEncryptionKeyCount(t *testing.T) {
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

	optionsSizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(optionsSizeBytes, 0)
	data = append(data, optionsSizeBytes...)

	numKeys := byte(0)
	data = append(data, numKeys)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

func TestReadLeaseSet2TooManyEncryptionKeys(t *testing.T) {
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

	optionsSizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(optionsSizeBytes, 0)
	data = append(data, optionsSizeBytes...)

	numKeys := byte(17)
	data = append(data, numKeys)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

func TestReadLeaseSet2TooManyLeases(t *testing.T) {
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

	optionsSizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(optionsSizeBytes, 0)
	data = append(data, optionsSizeBytes...)

	numKeys := byte(1)
	data = append(data, numKeys)
	keyTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyTypeBytes, key_certificate.KEYCERT_CRYPTO_X25519)
	data = append(data, keyTypeBytes...)
	keyLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLenBytes, 32)
	data = append(data, keyLenBytes...)
	data = append(data, make([]byte, 32)...)

	numLeases := byte(17)
	data = append(data, numLeases)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

func TestReadLeaseSet2WithOfflineKeys(t *testing.T) {
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

	// Truncated offline signature
	data = append(data, []byte{0x00, 0x00, 0x00}...)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

func TestReadLeaseSet2InvalidEncryptionKeyData(t *testing.T) {
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

	optionsSizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(optionsSizeBytes, 0)
	data = append(data, optionsSizeBytes...)

	numKeys := byte(1)
	data = append(data, numKeys)
	keyTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyTypeBytes, key_certificate.KEYCERT_CRYPTO_X25519)
	data = append(data, keyTypeBytes...)
	keyLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLenBytes, 32)
	data = append(data, keyLenBytes...)
	keyData := make([]byte, 10) // Too short
	data = append(data, keyData...)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

func TestReadLeaseSet2InvalidLeaseData(t *testing.T) {
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

	optionsSizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(optionsSizeBytes, 0)
	data = append(data, optionsSizeBytes...)

	numKeys := byte(1)
	data = append(data, numKeys)
	keyTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyTypeBytes, key_certificate.KEYCERT_CRYPTO_X25519)
	data = append(data, keyTypeBytes...)
	keyLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLenBytes, 32)
	data = append(data, keyLenBytes...)
	data = append(data, make([]byte, 32)...)

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

	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, 1735689600)
	data = append(data, publishedBytes...)

	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, 600)
	data = append(data, expiresBytes...)

	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, 0)
	data = append(data, flagsBytes...)

	optionsSizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(optionsSizeBytes, 0)
	data = append(data, optionsSizeBytes...)

	numKeys := byte(1)
	data = append(data, numKeys)
	keyTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyTypeBytes, key_certificate.KEYCERT_CRYPTO_X25519)
	data = append(data, keyTypeBytes...)
	keyLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLenBytes, 32)
	data = append(data, keyLenBytes...)
	data = append(data, make([]byte, 32)...)

	numLeases := byte(0)
	data = append(data, numLeases)

	truncatedSig := make([]byte, 20)
	data = append(data, truncatedSig...)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

//
// Constructor validation tests
//

func TestNewLeaseSet2ValidationErrors(t *testing.T) {
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	dest, _, err := destination.ReadDestination(destData)
	require.NoError(t, err)

	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	testCases := []struct {
		name           string
		expiresOffset  uint16
		flags          uint16
		offlineSig     *offline_signature.OfflineSignature
		encryptionKeys []EncryptionKey
		leases         []lease.Lease2
		expectError    bool
	}{
		{
			name:           "no leases rejected",
			expiresOffset:  600,
			flags:          0,
			offlineSig:     nil,
			encryptionKeys: []EncryptionKey{encKey},
			leases:         []lease.Lease2{},
			expectError:    true,
		},
		{
			name:           "no encryption keys",
			expiresOffset:  600,
			flags:          0,
			offlineSig:     nil,
			encryptionKeys: []EncryptionKey{},
			leases:         []lease.Lease2{},
			expectError:    true,
		},
		{
			name:           "too many encryption keys",
			expiresOffset:  600,
			flags:          0,
			offlineSig:     nil,
			encryptionKeys: make([]EncryptionKey, 17),
			leases:         []lease.Lease2{},
			expectError:    true,
		},
		{
			name:           "offline flag without signature",
			expiresOffset:  600,
			flags:          LEASESET2_FLAG_OFFLINE_KEYS,
			offlineSig:     nil,
			encryptionKeys: []EncryptionKey{encKey},
			leases:         []lease.Lease2{},
			expectError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewLeaseSet2(
				dest, uint32(time.Now().Unix()), tc.expiresOffset, tc.flags,
				tc.offlineSig, common.Mapping{}, tc.encryptionKeys, tc.leases, nil,
			)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConstructorRejectsZeroLeases(t *testing.T) {
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

func TestConstructorRejectsKeyLenMismatch(t *testing.T) {
	dest := createTestDest(t)
	l := createTestLease2(t, 0)

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

//
// Validate method tests
//

func TestValidateRejectsReservedFlags(t *testing.T) {
	ls2 := &LeaseSet2{
		flags:          0x0008, // reserved bit set
		encryptionKeys: []EncryptionKey{{KeyType: 4, KeyLen: 32, KeyData: make([]byte, 32)}},
	}
	err := ls2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reserved flag bits")
}

func TestValidateRejectsNoEncryptionKeys(t *testing.T) {
	ls2 := &LeaseSet2{encryptionKeys: []EncryptionKey{}}
	err := ls2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least 1 encryption key")
}

func TestValidateRejectsKeyLenMismatch(t *testing.T) {
	ls2 := &LeaseSet2{
		encryptionKeys: []EncryptionKey{
			{KeyType: key_certificate.KEYCERT_CRYPTO_X25519, KeyLen: 32, KeyData: make([]byte, 16)},
		},
	}
	err := ls2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestValidateRejectsKeyTypeSizeMismatch(t *testing.T) {
	ls2 := &LeaseSet2{
		encryptionKeys: []EncryptionKey{
			{KeyType: key_certificate.KEYCERT_CRYPTO_X25519, KeyLen: 64, KeyData: make([]byte, 64)},
		},
	}
	err := ls2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match expected size")
}

func TestValidateRejectsOfflineFlagWithoutSig(t *testing.T) {
	ls2 := &LeaseSet2{
		flags:          LEASESET2_FLAG_OFFLINE_KEYS,
		encryptionKeys: []EncryptionKey{{KeyType: 4, KeyLen: 32, KeyData: make([]byte, 32)}},
	}
	err := ls2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OFFLINE_KEYS flag")
}

func TestValidateRejectsTooManyLeases(t *testing.T) {
	ls2 := &LeaseSet2{
		encryptionKeys: []EncryptionKey{{KeyType: 4, KeyLen: 32, KeyData: make([]byte, 32)}},
		leases:         make([]lease.Lease2, 17),
	}
	err := ls2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too many leases")
}

//
// Parser lenient behavior tests
//

func TestParserAcceptsReservedFlagBits(t *testing.T) {
	data := buildMinimalLeaseSet2Data(t, key_certificate.KEYCERT_SIGN_ED25519, 0, 0x0008)
	ls2, _, err := ReadLeaseSet2(data)
	assert.NoError(t, err)
	assert.Equal(t, uint16(0x0008), ls2.Flags()&0xFFF8,
		"Reserved flag bits should be preserved in parsed value")
}

func TestParserWarnsOnEncKeyTypeLenMismatch(t *testing.T) {
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
	data = append(data, 0x01)       // 1 key
	keyTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyTypeBytes, key_certificate.KEYCERT_CRYPTO_X25519)
	data = append(data, keyTypeBytes...)
	keyLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLenBytes, 64) // wrong: X25519 should be 32
	data = append(data, keyLenBytes...)
	data = append(data, make([]byte, 64)...)    // 64 bytes of key data
	data = append(data, 0x00)                   // 0 leases
	data = append(data, make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)...)

	ls2, _, err := ReadLeaseSet2(data)
	assert.NoError(t, err)
	assert.Equal(t, uint16(64), ls2.EncryptionKeys()[0].KeyLen)
}

func TestParserAcceptsZeroLeases(t *testing.T) {
	data := buildMinimalLeaseSet2Data(t, key_certificate.KEYCERT_SIGN_ED25519, 0, 0)
	ls2, _, err := ReadLeaseSet2(data)
	assert.NoError(t, err, "Parser should accept 0 leases (lenient parsing)")
	assert.Equal(t, 0, ls2.LeaseCount())
}
