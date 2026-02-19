package encrypted_leaseset

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/common/key_certificate"
	"github.com/stretchr/testify/assert"
)

// ————————————————————————————————————————————————
// Validation tests for ReadEncryptedLeaseSet and Validate()
// Source: encrypted_leaseset.go
// ————————————————————————————————————————————————

func TestReadEncryptedLeaseSetTooShort(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"Empty", 0},
		{"100 bytes", 100},
		{"Just under minimum", ENCRYPTED_LEASESET_MIN_SIZE - 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ReadEncryptedLeaseSet(make([]byte, tt.size))
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "too short")
		})
	}
}

func TestReadEncryptedLeaseSetZeroInnerLength(t *testing.T) {
	data := make([]byte, 0, 120)
	// sig_type = Ed25519
	data = append(data, 0x00, 0x07)
	// blinded key (32)
	data = append(data, make([]byte, 32)...)
	// published (4)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(time.Now().Unix()))
	data = append(data, buf...)
	// expires (2) = 600
	data = append(data, 0x02, 0x58)
	// flags (2) = 0
	data = append(data, 0x00, 0x00)
	// inner_length = 0 (invalid)
	data = append(data, 0x00, 0x00)
	// Add 1 dummy byte so total >= 109 minimum, then 64-byte signature
	data = append(data, 0x00)
	data = append(data, make([]byte, 64)...)

	_, _, err := ReadEncryptedLeaseSet(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "inner length cannot be zero")
}

func TestReadEncryptedLeaseSetReservedFlags(t *testing.T) {
	data := createSpecCompliantELS(t, 100, 0x0004) // bit 2

	_, _, err := ReadEncryptedLeaseSet(data)
	assert.Error(t, err, "reserved flag bits must cause rejection")
	assert.Contains(t, err.Error(), "reserved flag bits")
}

func TestEncryptedLeaseSetUnknownSigType(t *testing.T) {
	data := make([]byte, 200)
	binary.BigEndian.PutUint16(data[:2], 999)
	_, _, err := ReadEncryptedLeaseSet(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown signing key type")
}

func TestEncryptedLeaseSetValidate(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		var els *EncryptedLeaseSet
		assert.Error(t, els.Validate())
	})

	t.Run("unknown sig_type", func(t *testing.T) {
		els := &EncryptedLeaseSet{sigType: 999}
		assert.ErrorContains(t, els.Validate(), "unknown sig_type")
	})

	t.Run("wrong key size", func(t *testing.T) {
		els := &EncryptedLeaseSet{
			sigType:          key_certificate.KEYCERT_SIGN_ED25519,
			blindedPublicKey: make([]byte, 16), // wrong size
		}
		assert.ErrorContains(t, els.Validate(), "blinded public key size")
	})

	t.Run("zero expires", func(t *testing.T) {
		els := &EncryptedLeaseSet{
			sigType:          key_certificate.KEYCERT_SIGN_ED25519,
			blindedPublicKey: make([]byte, 32),
			expires:          0,
		}
		assert.ErrorContains(t, els.Validate(), "expires offset cannot be zero")
	})

	t.Run("reserved flags set", func(t *testing.T) {
		els := &EncryptedLeaseSet{
			sigType:          key_certificate.KEYCERT_SIGN_ED25519,
			blindedPublicKey: make([]byte, 32),
			expires:          600,
			flags:            0x0004, // reserved bit 2
		}
		assert.ErrorContains(t, els.Validate(), "reserved flag bits")
	})

	t.Run("empty encrypted data", func(t *testing.T) {
		els := &EncryptedLeaseSet{
			sigType:            key_certificate.KEYCERT_SIGN_ED25519,
			blindedPublicKey:   make([]byte, 32),
			expires:            600,
			encryptedInnerData: []byte{},
		}
		assert.ErrorContains(t, els.Validate(), "cannot be empty")
	})

	t.Run("encrypted data below minimum crypto overhead", func(t *testing.T) {
		els := &EncryptedLeaseSet{
			sigType:            key_certificate.KEYCERT_SIGN_ED25519,
			blindedPublicKey:   make([]byte, 32),
			expires:            600,
			innerLength:        50,
			encryptedInnerData: make([]byte, 50), // < 61 minimum
		}
		assert.ErrorContains(t, els.Validate(), "too small")
	})
}

// TestEncryptedInnerDataMinimumCryptoOverhead verifies finding #11:
// Validate() checks minimum crypto overhead size.
func TestEncryptedInnerDataMinimumCryptoOverhead(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)

	smallData := make([]byte, 60)
	_, err = NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		pub,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		smallData,
		priv,
	)
	assert.Error(t, err, "encrypted data below minimum crypto overhead should be rejected")
	assert.Contains(t, err.Error(), "encrypted inner data size")
}
