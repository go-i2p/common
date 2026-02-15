// Package meta_leaseset implements the I2P MetaLeaseSet common data structure
package meta_leaseset

import (
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// META_LEASESET_DBSTORE_TYPE is the DatabaseStore type byte for MetaLeaseSet.
// Per the I2P spec, the signature is computed over all serialised data
// PREPENDED with this single byte.
const META_LEASESET_DBSTORE_TYPE = 0x07

// Verify verifies the cryptographic signature of the MetaLeaseSet.
//
// Per the I2P specification, the signature for a MetaLeaseSet is computed over
// the serialised content PREPENDED with a single byte containing the
// DatabaseStore type (0x07). The verified data is:
//
//	[]byte{0x07} + Bytes()[:len(Bytes()) - signatureLength]
//
// The signature is verified against the Destination's signing public key,
// or the transient signing public key if offline signatures are present.
//
// Returns nil if the signature is valid, or an error describing the failure.
func (mls *MetaLeaseSet) Verify() error {
	log.Debug("Verifying MetaLeaseSet signature")

	// Serialize the full MetaLeaseSet (including the trailing signature)
	fullBytes, err := mls.Bytes()
	if err != nil {
		return oops.Errorf("failed to serialize MetaLeaseSet for verification: %w", err)
	}

	// Get the signature bytes and length
	sigBytes := mls.signature.Bytes()
	sigLen := len(sigBytes)

	if len(fullBytes) < sigLen {
		return oops.Errorf("MetaLeaseSet data too short for signature verification")
	}

	// Data to verify: type byte prefix + everything except the trailing signature
	contentBytes := fullBytes[:len(fullBytes)-sigLen]
	dataToVerify := make([]byte, 0, 1+len(contentBytes))
	dataToVerify = append(dataToVerify, META_LEASESET_DBSTORE_TYPE)
	dataToVerify = append(dataToVerify, contentBytes...)

	// Determine which signing public key to use for verification
	signingPubKey, err := mls.signingPublicKeyForVerification()
	if err != nil {
		return oops.Errorf("failed to get signing public key for verification: %w", err)
	}

	// Create verifier and verify
	verifier, err := signingPubKey.NewVerifier()
	if err != nil {
		return oops.Errorf("failed to create verifier: %w", err)
	}

	if err := verifier.Verify(dataToVerify, sigBytes); err != nil {
		log.WithError(err).Warn("MetaLeaseSet signature verification failed")
		return oops.Errorf("MetaLeaseSet signature verification failed: %w", err)
	}

	log.Debug("MetaLeaseSet signature verification succeeded")
	return nil
}

// signingPublicKeyForVerification returns the appropriate signing public key
// for signature verification. If offline keys are present, the transient
// signing public key from the OfflineSignature is constructed and returned.
// Otherwise, the Destination's signing public key is returned.
func (mls *MetaLeaseSet) signingPublicKeyForVerification() (types.SigningPublicKey, error) {
	if mls.HasOfflineKeys() && mls.offlineSignature != nil {
		// Use transient signing public key from offline signature
		transientKeyBytes := mls.offlineSignature.TransientPublicKey()
		transientSigType := mls.offlineSignature.TransientSigType()
		spk, err := key_certificate.ConstructSigningPublicKeyByType(transientKeyBytes, int(transientSigType))
		if err != nil {
			return nil, oops.Errorf("failed to construct transient signing public key: %w", err)
		}
		return spk, nil
	}

	// Use destination's signing public key
	spk, err := mls.destination.SigningPublicKey()
	if err != nil {
		return nil, oops.Errorf("failed to get signing public key from Destination: %w", err)
	}
	return spk, nil
}
