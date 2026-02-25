package lease_set2

import (
	"crypto/ed25519"
	"github.com/go-i2p/crypto/rand"
	"encoding/binary"
	"testing"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/signature"
)

func FuzzReadLeaseSet2(f *testing.F) {
	// Build a valid seed inline since buildMinimalLeaseSet2Data takes *testing.T
	seed := func() []byte {
		destData := make([]byte, 391)
		copy(destData[0:], make([]byte, 256))   // public key
		copy(destData[256:], make([]byte, 128)) // signing key padding
		destData[384] = 0x05                    // cert type = key cert
		destData[385] = 0x00                    // cert length high byte
		destData[386] = 0x04                    // cert length = 4
		binary.BigEndian.PutUint16(destData[387:389], key_certificate.KEYCERT_SIGN_ED25519)
		binary.BigEndian.PutUint16(destData[389:391], 0) // crypto type default

		data := destData
		publishedBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(publishedBytes, 1735689600)
		data = append(data, publishedBytes...)
		expiresBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(expiresBytes, 600)
		data = append(data, expiresBytes...)
		data = append(data, 0x00, 0x00) // flags
		data = append(data, 0x00, 0x00) // empty options

		// 1 encryption key
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
		binary.BigEndian.PutUint32(endDate, 1735690200)
		data = append(data, endDate...)

		// signature
		data = append(data, make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)...)
		return data
	}()

	f.Add(seed)
	f.Add([]byte{})
	if len(seed) > 50 {
		f.Add(seed[:50])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		ls2, _, err := ReadLeaseSet2(data)
		if err != nil {
			return
		}
		_ = ls2.Destination()
		_ = ls2.Published()
		_ = ls2.Expires()
		_ = ls2.Flags()
		_ = ls2.HasOfflineKeys()
		_ = ls2.IsUnpublished()
		_ = ls2.IsBlinded()
		_ = ls2.EncryptionKeys()
		_ = ls2.EncryptionKeyCount()
		_ = ls2.Leases()
		_ = ls2.LeaseCount()
		_ = ls2.Signature()
		_ = ls2.Options()
		_, _ = ls2.Bytes()
	})
}

func FuzzNewLeaseSet2Constructor(f *testing.F) {
	f.Add(uint32(1735689600), uint16(600), uint16(0), uint8(1), uint8(1))
	f.Add(uint32(0), uint16(0), uint16(0), uint8(1), uint8(1))
	f.Add(uint32(4294967295), uint16(65535), uint16(7), uint8(16), uint8(16))

	f.Fuzz(func(t *testing.T, published uint32, expires uint16, flags uint16, numKeys uint8, numLeases uint8) {
		if numKeys < 1 || numKeys > 16 {
			return
		}
		if numLeases < 1 || numLeases > 16 {
			return
		}

		dest := createTestDest(t)
		encKeys := make([]EncryptionKey, numKeys)
		for i := range encKeys {
			encKeys[i] = EncryptionKey{
				KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
				KeyLen:  32,
				KeyData: make([]byte, 32),
			}
		}
		leases := make([]lease.Lease2, numLeases)
		for i := range leases {
			l := createTestLease2(t, i)
			leases[i] = *l
		}

		_, pub, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return
		}

		ls2, err := NewLeaseSet2(dest, published, expires, flags, nil, common.Mapping{}, encKeys, leases, pub)
		if err != nil {
			return // validation error is fine
		}
		_ = ls2.Validate()
		_, _ = ls2.Bytes()
	})
}
