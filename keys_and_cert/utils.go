// Package keys_and_cert implements the I2P KeysAndCert common data structure
package keys_and_cert

import (
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/samber/oops"

	"github.com/go-i2p/common/key_certificate"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/types"
)

// constructPublicKey constructs a public key from raw data based on crypto type.
// Supports ElGamal (type 0) and X25519 (type 4) encryption key types.
func constructPublicKey(data []byte, cryptoType uint16) (types.ReceivingPublicKey, error) {
	switch cryptoType {
	case key_certificate.CRYPTO_KEY_TYPE_ELGAMAL:
		if len(data) != 256 {
			return nil, oops.Errorf("invalid ElGamal public key length: expected 256, got %d", len(data))
		}
		var elgPublicKey elgamal.ElgPublicKey
		copy(elgPublicKey[:], data)
		return elgPublicKey, nil
	case key_certificate.KEYCERT_CRYPTO_X25519:
		if len(data) != 32 {
			return nil, oops.Errorf("invalid X25519 public key length: expected 32, got %d", len(data))
		}
		x25519Key := make(curve25519.Curve25519PublicKey, 32)
		copy(x25519Key, data)
		return x25519Key, nil
	default:
		return nil, oops.Errorf("unsupported crypto key type: %d", cryptoType)
	}
}

// constructSigningPublicKey constructs a signing public key from raw data based on signature type.
// Supports Ed25519 (type 7), Ed25519ph (type 8), and RedDSA (type 11) signing key types.
func constructSigningPublicKey(data []byte, sigType uint16) (types.SigningPublicKey, error) {
	switch sigType {
	case key_certificate.SIGNATURE_TYPE_ED25519_SHA512:
		return constructEd25519SigningKey(data, "Ed25519")
	case key_certificate.KEYCERT_SIGN_ED25519PH:
		return constructEd25519SigningKey(data, "Ed25519ph")
	case key_certificate.KEYCERT_SIGN_REDDSA_ED25519:
		return constructEd25519SigningKey(data, "RedDSA")
	default:
		return nil, oops.Errorf("unsupported signature key type: %d", sigType)
	}
}

// constructEd25519SigningKey constructs an Ed25519-family signing key from raw data.
// Used for Ed25519, Ed25519ph, and RedDSA which share the same 32-byte key format.
func constructEd25519SigningKey(data []byte, keyName string) (types.SigningPublicKey, error) {
	if len(data) != 32 {
		return nil, oops.Errorf("invalid %s public key length: expected 32, got %d", keyName, len(data))
	}
	key, err := ed25519.NewEd25519PublicKey(data)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct %s signing key", keyName)
	}
	return key, nil
}
