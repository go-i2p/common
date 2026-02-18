// Package encrypted_leaseset implements the I2P EncryptedLeaseSet common data structure
package encrypted_leaseset

import (
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// Verify verifies the cryptographic signature of the EncryptedLeaseSet.
//
// Per the I2P specification, the signature covers: 0x05 || content_without_signature.
// The signing public key is the blinded public key, or the transient key if offline
// signatures are present.
func (els *EncryptedLeaseSet) Verify() error {
	log.Debug("Verifying EncryptedLeaseSet signature")

	// Serialize: type byte + content without signature
	dataToVerify, err := els.dataForSigning()
	if err != nil {
		return oops.Errorf("failed to serialize for verification: %w", err)
	}

	sigBytes := els.signature.Bytes()

	// Determine the signing public key
	signingPubKey, err := els.signingPublicKeyForVerification()
	if err != nil {
		return oops.Errorf("failed to get signing public key: %w", err)
	}

	// Create verifier and verify
	verifier, err := signingPubKey.NewVerifier()
	if err != nil {
		return oops.Errorf("failed to create verifier: %w", err)
	}

	if err := verifier.Verify(dataToVerify, sigBytes); err != nil {
		log.WithError(err).Warn("EncryptedLeaseSet signature verification failed")
		return oops.Errorf("signature verification failed: %w", err)
	}

	log.Debug("EncryptedLeaseSet signature verification succeeded")
	return nil
}

// signingPublicKeyForVerification returns the appropriate signing public key
// for signature verification. Uses the transient key from OfflineSignature if
// present, otherwise constructs a key from sigType + blindedPublicKey.
func (els *EncryptedLeaseSet) signingPublicKeyForVerification() (types.SigningPublicKey, error) {
	if els.HasOfflineKeys() && els.offlineSignature != nil {
		transientKeyBytes := els.offlineSignature.TransientPublicKey()
		transientSigType := els.offlineSignature.TransientSigType()
		spk, err := key_certificate.ConstructSigningPublicKeyByType(
			transientKeyBytes, int(transientSigType))
		if err != nil {
			return nil, oops.Errorf("failed to construct transient signing public key: %w", err)
		}
		return spk, nil
	}

	// Construct from sigType + blindedPublicKey
	spk, err := key_certificate.ConstructSigningPublicKeyByType(
		els.blindedPublicKey, int(els.sigType))
	if err != nil {
		return nil, oops.Errorf("failed to construct blinded signing public key: %w", err)
	}
	return spk, nil
}
