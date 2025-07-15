// Package keys_and_cert implements the I2P KeysAndCert common data structure
package keys_and_cert

import (
	"github.com/go-i2p/crypto/ed25519"
	"github.com/samber/oops"

	"github.com/go-i2p/common/key_certificate"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/types"
)

// constructPublicKey constructs a public key from raw data based on crypto type.
func constructPublicKey(data []byte, cryptoType uint16) (types.ReceivingPublicKey, error) {
	switch cryptoType {
	case key_certificate.CRYPTO_KEY_TYPE_ELGAMAL:
		if len(data) != 256 {
			return nil, oops.Errorf("invalid ElGamal public key length")
		}
		var elgPublicKey elgamal.ElgPublicKey
		copy(elgPublicKey[:], data)
		return elgPublicKey, nil
	// Handle other crypto types...
	default:
		return nil, oops.Errorf("unsupported crypto key type: %d", cryptoType)
	}
}

// constructSigningPublicKey constructs a signing public key from raw data based on signature type.
func constructSigningPublicKey(data []byte, sigType uint16) (types.SigningPublicKey, error) {
	switch sigType {
	case key_certificate.SIGNATURE_TYPE_ED25519_SHA512:
		if len(data) != 32 {
			return nil, oops.Errorf("invalid Ed25519 public key length")
		}
		return ed25519.Ed25519PublicKey(data), nil
	// Handle other signature types...
	default:
		return nil, oops.Errorf("unsupported signature key type: %d", sigType)
	}
}
