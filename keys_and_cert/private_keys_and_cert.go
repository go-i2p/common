package keys_and_cert

import (
	"bytes"

	"github.com/samber/oops"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/crypto/types"
)

// PrivateKeysAndCert contains a KeysAndCert along with the corresponding private keys for the
// Public Key and the Signing Public Key.
//
// PK_KEY and SPK_KEY use typed interfaces (types.PrivateEncryptionKey and
// types.SigningPrivateKey) instead of the bare crypto.PrivateKey (any) alias,
// providing compile-time type safety and preventing arbitrary values from being
// stored without satisfying the required cryptographic contracts.
type PrivateKeysAndCert struct {
	KeysAndCert
	PK_KEY  types.PrivateEncryptionKey // Encryption private key
	SPK_KEY types.SigningPrivateKey    // Signing private key
}

// NewPrivateKeysAndCert creates a new PrivateKeysAndCert instance with the provided parameters.
// It validates the embedded KeysAndCert and ensures both private keys are non-nil.
func NewPrivateKeysAndCert(
	keyCertificate *key_certificate.KeyCertificate,
	publicKey types.ReceivingPublicKey,
	padding []byte,
	signingPublicKey types.SigningPublicKey,
	encryptionPrivateKey types.PrivateEncryptionKey,
	signingPrivateKey types.SigningPrivateKey,
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

	pkac := &PrivateKeysAndCert{
		KeysAndCert: *kac,
		PK_KEY:      encryptionPrivateKey,
		SPK_KEY:     signingPrivateKey,
	}

	// Validate key correspondence before returning
	if err := pkac.validateKeyCorrespondence(); err != nil {
		return nil, oops.Wrapf(err, "private/public key mismatch")
	}

	return pkac, nil
}

// PrivateKey returns the encryption private key.
func (pkac *PrivateKeysAndCert) PrivateKey() types.PrivateEncryptionKey {
	if pkac == nil {
		return nil
	}
	return pkac.PK_KEY
}

// SigningPrivateKey returns the signing private key.
func (pkac *PrivateKeysAndCert) SigningPrivateKey() types.SigningPrivateKey {
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
	// Validate that private keys correspond to the public keys
	if err := pkac.validateKeyCorrespondence(); err != nil {
		return oops.Wrapf(err, "key correspondence validation failed")
	}
	return nil
}

// validateKeyCorrespondence checks that the private keys correspond to the stored public keys.
// Returns an error if the derived public keys do not match or if types are mismatched.
// If the keys do not support public key derivation, validation is skipped.
func (pkac *PrivateKeysAndCert) validateKeyCorrespondence() error {
	if pkac == nil {
		return oops.Errorf("PrivateKeysAndCert is nil")
	}

	// Validate encryption key correspondence
	derivedEncryptionPub, err := pkac.PK_KEY.Public()
	if err == nil && derivedEncryptionPub != nil {
		// Get the bytes from the derived public key if available
		if derivedEncryptionBytes, ok := derivedEncryptionPub.(interface{ Bytes() []byte }); ok {
			// Compare the derived bytes with the stored public key bytes
			storedEncryptionBytes := pkac.ReceivingPublic.Bytes()
			if !bytes.Equal(derivedEncryptionBytes.Bytes(), storedEncryptionBytes) {
				return oops.Errorf("derived public encryption key does not match stored receiving public key")
			}

			// Validate type correspondence for encryption key if available
			if typedEncryptionKey, ok := derivedEncryptionPub.(interface{ PublicKeyType() int }); ok {
				if typedEncryptionKey.PublicKeyType() != pkac.KeyCertificate.PublicKeyType() {
					return oops.Errorf("derived encryption key type %d does not match certificate encryption key type %d",
						typedEncryptionKey.PublicKeyType(), pkac.KeyCertificate.PublicKeyType())
				}
			}
		}
	}

	// Validate signing key correspondence
	derivedSigningPub, err := pkac.SPK_KEY.Public()
	if err == nil && derivedSigningPub != nil {
		// Get the bytes from the derived public key if available
		if derivedSigningBytes, ok := derivedSigningPub.(interface{ Bytes() []byte }); ok {
			// Compare the derived bytes with the stored public key bytes
			storedSigningBytes := pkac.SigningPublic.Bytes()
			if !bytes.Equal(derivedSigningBytes.Bytes(), storedSigningBytes) {
				return oops.Errorf("derived public signing key does not match stored signing public key")
			}

			// Validate type correspondence for signing key if available
			if typedSigningKey, ok := derivedSigningPub.(interface{ SigningPublicKeyType() int }); ok {
				if typedSigningKey.SigningPublicKeyType() != pkac.KeyCertificate.SigningPublicKeyType() {
					return oops.Errorf("derived signing key type %d does not match certificate signing key type %d",
						typedSigningKey.SigningPublicKeyType(), pkac.KeyCertificate.SigningPublicKeyType())
				}
			}
		}
	}

	return nil
}
