// Package keys_and_cert implements the I2P KeysAndCert common data structure
package keys_and_cert

import (
	"crypto"

	"github.com/samber/oops"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/crypto/types"
)

// PrivateKeysAndCert contains a KeysAndCert along with the corresponding private keys for the
// Public Key and the Signing Public Key.
type PrivateKeysAndCert struct {
	KeysAndCert
	PK_KEY  crypto.PrivateKey // Encryption private key
	SPK_KEY crypto.PrivateKey // Signing private key
}

// NewPrivateKeysAndCert creates a new PrivateKeysAndCert instance with the provided parameters.
// It validates the embedded KeysAndCert and ensures both private keys are non-nil.
func NewPrivateKeysAndCert(
	keyCertificate *key_certificate.KeyCertificate,
	publicKey types.ReceivingPublicKey,
	padding []byte,
	signingPublicKey types.SigningPublicKey,
	encryptionPrivateKey crypto.PrivateKey,
	signingPrivateKey crypto.PrivateKey,
) (*PrivateKeysAndCert, error) {
	if encryptionPrivateKey == nil {
		return nil, oops.Errorf("encryption private key (PK_KEY) is required")
	}
	if signingPrivateKey == nil {
		return nil, oops.Errorf("signing private key (SPK_KEY) is required")
	}

	kac, err := NewKeysAndCert(keyCertificate, publicKey, padding, signingPublicKey)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create embedded KeysAndCert")
	}

	return &PrivateKeysAndCert{
		KeysAndCert: *kac,
		PK_KEY:      encryptionPrivateKey,
		SPK_KEY:     signingPrivateKey,
	}, nil
}

// PrivateKey returns the encryption private key.
func (pkac *PrivateKeysAndCert) PrivateKey() crypto.PrivateKey {
	if pkac == nil {
		return nil
	}
	return pkac.PK_KEY
}

// SigningPrivateKey returns the signing private key.
func (pkac *PrivateKeysAndCert) SigningPrivateKey() crypto.PrivateKey {
	if pkac == nil {
		return nil
	}
	return pkac.SPK_KEY
}

// Validate checks if the PrivateKeysAndCert is fully initialized.
// Returns an error if any required field is nil or the embedded KeysAndCert is invalid.
func (pkac *PrivateKeysAndCert) Validate() error {
	if pkac == nil {
		return oops.Errorf("PrivateKeysAndCert is nil")
	}
	if err := pkac.KeysAndCert.Validate(); err != nil {
		return oops.Errorf("embedded KeysAndCert is invalid: %w", err)
	}
	if pkac.PK_KEY == nil {
		return oops.Errorf("encryption private key (PK_KEY) is required")
	}
	if pkac.SPK_KEY == nil {
		return oops.Errorf("signing private key (SPK_KEY) is required")
	}
	return nil
}
