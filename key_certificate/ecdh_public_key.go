// Package key_certificate implements the I2P Destination common data structure
package key_certificate

import (
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// ecdhPublicKey is a minimal holder for ECDH (NIST P-256/384/521) public key
// bytes as extracted from a KeysAndCert structure.  It implements
// types.ReceivingPublicKey so that callers can obtain the raw key bytes and
// determine the key type without requiring a full ECIES encryption stack.
//
// NewEncrypter returns an explicit "not implemented" error because full ECIES
// encryption (ECDH key-agreement + AES-CBC-256 + HMAC-SHA256) for these types
// is not yet available via the go-i2p/crypto module.  The key bytes are fully
// accessible via Bytes()/Len() for callers that implement the protocol layer
// themselves.
type ecdhPublicKey struct {
	keyBytes []byte
	label    string // for diagnostics, e.g. "ECDH-P256"
}

func (k *ecdhPublicKey) NewEncrypter() (types.Encrypter, error) {
	return nil, oops.Errorf("%s encryption (ECIES) is not yet implemented in go-i2p/crypto", k.label)
}

func (k *ecdhPublicKey) Len() int      { return len(k.keyBytes) }
func (k *ecdhPublicKey) Bytes() []byte { return append([]byte(nil), k.keyBytes...) }

// newECDHP256PublicKey creates a ReceivingPublicKey holding a 64-byte P-256
// public key (uncompressed X||Y point, start-aligned in the 256-byte field).
func newECDHP256PublicKey(data []byte) (types.ReceivingPublicKey, error) {
	if len(data) < KEYCERT_CRYPTO_P256_SIZE {
		return nil, oops.Errorf("insufficient data for ECDH-P256 key: need %d bytes, got %d",
			KEYCERT_CRYPTO_P256_SIZE, len(data))
	}
	dst := make([]byte, KEYCERT_CRYPTO_P256_SIZE)
	copy(dst, data[:KEYCERT_CRYPTO_P256_SIZE])
	return &ecdhPublicKey{keyBytes: dst, label: "ECDH-P256"}, nil
}

// newECDHP384PublicKey creates a ReceivingPublicKey holding a 96-byte P-384
// public key (uncompressed X||Y point, start-aligned in the 256-byte field).
func newECDHP384PublicKey(data []byte) (types.ReceivingPublicKey, error) {
	if len(data) < KEYCERT_CRYPTO_P384_SIZE {
		return nil, oops.Errorf("insufficient data for ECDH-P384 key: need %d bytes, got %d",
			KEYCERT_CRYPTO_P384_SIZE, len(data))
	}
	dst := make([]byte, KEYCERT_CRYPTO_P384_SIZE)
	copy(dst, data[:KEYCERT_CRYPTO_P384_SIZE])
	return &ecdhPublicKey{keyBytes: dst, label: "ECDH-P384"}, nil
}

// newECDHP521PublicKey creates a ReceivingPublicKey holding a 132-byte P-521
// public key (uncompressed X||Y point).  P-521 keys exceed KEYCERT_PUBKEY_SIZE
// (256 > 132, so no overflow for crypto, but note the SPK side has excess when
// P-521 is used as a signing type).
func newECDHP521PublicKey(data []byte) (types.ReceivingPublicKey, error) {
	if len(data) < KEYCERT_CRYPTO_P521_SIZE {
		return nil, oops.Errorf("insufficient data for ECDH-P521 key: need %d bytes, got %d",
			KEYCERT_CRYPTO_P521_SIZE, len(data))
	}
	dst := make([]byte, KEYCERT_CRYPTO_P521_SIZE)
	copy(dst, data[:KEYCERT_CRYPTO_P521_SIZE])
	return &ecdhPublicKey{keyBytes: dst, label: "ECDH-P521"}, nil
}
