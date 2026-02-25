// Package key_certificate implements the I2P KeyCertificate common data structure
package key_certificate

import (
	"github.com/go-i2p/crypto/ecdsa"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// ecdhPublicKey wraps an upstream ecdsa.ECP* public key as a ReceivingPublicKey.
// ECDH and ECDSA use the same uncompressed-point format; we reuse upstream
// constructors for size validation and byte storage while adding NewEncrypter,
// which returns "not yet implemented" because ECIES-P* is not yet in go-i2p/crypto.
type ecdhPublicKey struct {
	inner interface {
		Len() int
		Bytes() []byte
	}
	label string // diagnostic label, e.g. "ECDH-P256"
}

func (k *ecdhPublicKey) NewEncrypter() (types.Encrypter, error) {
	return nil, oops.Errorf("%s encryption (ECIES) is not yet implemented in go-i2p/crypto", k.label)
}

func (k *ecdhPublicKey) Len() int      { return k.inner.Len() }
func (k *ecdhPublicKey) Bytes() []byte { return k.inner.Bytes() }

// newECDHP256PublicKey creates a ReceivingPublicKey for a 64-byte P-256
// public key (uncompressed X||Y point, start-aligned in the 256-byte field).
// Validation is delegated to ecdsa.NewECP256PublicKey.
func newECDHP256PublicKey(data []byte) (types.ReceivingPublicKey, error) {
	if len(data) < KEYCERT_CRYPTO_P256_SIZE {
		return nil, oops.Errorf("insufficient data for ECDH-P256 key: need %d bytes, got %d",
			KEYCERT_CRYPTO_P256_SIZE, len(data))
	}
	k, err := ecdsa.NewECP256PublicKey(data[:KEYCERT_CRYPTO_P256_SIZE])
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct ECDH-P256 public key")
	}
	return &ecdhPublicKey{inner: k, label: "ECDH-P256"}, nil
}

// newECDHP384PublicKey creates a ReceivingPublicKey for a 96-byte P-384
// public key (uncompressed X||Y point, start-aligned in the 256-byte field).
// Validation is delegated to ecdsa.NewECP384PublicKey.
func newECDHP384PublicKey(data []byte) (types.ReceivingPublicKey, error) {
	if len(data) < KEYCERT_CRYPTO_P384_SIZE {
		return nil, oops.Errorf("insufficient data for ECDH-P384 key: need %d bytes, got %d",
			KEYCERT_CRYPTO_P384_SIZE, len(data))
	}
	k, err := ecdsa.NewECP384PublicKey(data[:KEYCERT_CRYPTO_P384_SIZE])
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct ECDH-P384 public key")
	}
	return &ecdhPublicKey{inner: k, label: "ECDH-P384"}, nil
}

// newECDHP521PublicKey creates a ReceivingPublicKey for a 132-byte P-521
// public key (uncompressed X||Y point, start-aligned in the 256-byte field).
// Validation is delegated to ecdsa.NewECP521PublicKey.
func newECDHP521PublicKey(data []byte) (types.ReceivingPublicKey, error) {
	if len(data) < KEYCERT_CRYPTO_P521_SIZE {
		return nil, oops.Errorf("insufficient data for ECDH-P521 key: need %d bytes, got %d",
			KEYCERT_CRYPTO_P521_SIZE, len(data))
	}
	k, err := ecdsa.NewECP521PublicKey(data[:KEYCERT_CRYPTO_P521_SIZE])
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct ECDH-P521 public key")
	}
	return &ecdhPublicKey{inner: k, label: "ECDH-P521"}, nil
}
