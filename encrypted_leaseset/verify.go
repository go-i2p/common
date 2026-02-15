// Package encrypted_leaseset implements the I2P EncryptedLeaseSet common data structure
package encrypted_leaseset

import (
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// ENCRYPTED_LEASESET_DBSTORE_TYPE is the DatabaseStore type byte for EncryptedLeaseSet.
// Per the I2P spec, the signature is computed over all serialised data
// PREPENDED with this single byte.
const ENCRYPTED_LEASESET_DBSTORE_TYPE = 0x05

// Verify verifies the cryptographic signature of the EncryptedLeaseSet.
//
// Per the I2P specification, the signature for an EncryptedLeaseSet is computed over
// the serialised content PREPENDED with a single byte containing the
// DatabaseStore type (0x05). The verified data is:
//
//	[]byte{0x05} + Bytes()[:len(Bytes()) - signatureLength]
//
// The signature is verified against the blinded destination's signing public key,
// or the transient signing public key if offline signatures are present.
//
// Returns nil if the signature is valid, or an error describing the failure.
func (els *EncryptedLeaseSet) Verify() error {
	log.Debug("Verifying EncryptedLeaseSet signature")

	// Serialize the full EncryptedLeaseSet (including the trailing signature)
	fullBytes, err := els.Bytes()
	if err != nil {
		return oops.Errorf("failed to serialize EncryptedLeaseSet for verification: %w", err)
	}

	// Get the signature bytes and length
	sigBytes := els.signature.Bytes()
	sigLen := len(sigBytes)

	if len(fullBytes) < sigLen {
		return oops.Errorf("EncryptedLeaseSet data too short for signature verification")
	}

	// Data to verify: type byte prefix + everything except the trailing signature
	contentBytes := fullBytes[:len(fullBytes)-sigLen]
	dataToVerify := make([]byte, 0, 1+len(contentBytes))
	dataToVerify = append(dataToVerify, ENCRYPTED_LEASESET_DBSTORE_TYPE)
	dataToVerify = append(dataToVerify, contentBytes...)

	// Determine which signing public key to use for verification
	signingPubKey, err := els.signingPublicKeyForVerification()
	if err != nil {
		return oops.Errorf("failed to get signing public key for verification: %w", err)
	}

	// Create verifier and verify
	verifier, err := signingPubKey.NewVerifier()
	if err != nil {
		return oops.Errorf("failed to create verifier: %w", err)
	}

	if err := verifier.Verify(dataToVerify, sigBytes); err != nil {
		log.WithError(err).Warn("EncryptedLeaseSet signature verification failed")
		return oops.Errorf("EncryptedLeaseSet signature verification failed: %w", err)
	}

	log.Debug("EncryptedLeaseSet signature verification succeeded")
	return nil
}

// signingPublicKeyForVerification returns the appropriate signing public key
// for signature verification. If offline keys are present, the transient
// signing public key from the OfflineSignature is constructed and returned.
// Otherwise, the blinded destination's signing public key is returned.
func (els *EncryptedLeaseSet) signingPublicKeyForVerification() (types.SigningPublicKey, error) {
	if els.HasOfflineKeys() && els.offlineSignature != nil {
		// Use transient signing public key from offline signature
		transientKeyBytes := els.offlineSignature.TransientPublicKey()
		transientSigType := els.offlineSignature.TransientSigType()
		spk, err := key_certificate.ConstructSigningPublicKeyByType(transientKeyBytes, int(transientSigType))
		if err != nil {
			return nil, oops.Errorf("failed to construct transient signing public key: %w", err)
		}
		return spk, nil
	}

	// Use blinded destination's signing public key
	spk, err := els.blindedDestination.SigningPublicKey()
	if err != nil {
		return nil, oops.Errorf("failed to get signing public key from blinded destination: %w", err)
	}
	return spk, nil
}
