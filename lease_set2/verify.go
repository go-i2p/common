// Package lease_set2 implements the I2P LeaseSet2 common data structure
package lease_set2

import (
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// LEASESET2_DBSTORE_TYPE is the DatabaseStore type byte for LeaseSet2.
// Per the I2P spec, the signature is computed over all serialised data
// PREPENDED with this single byte.
const LEASESET2_DBSTORE_TYPE = 0x03

// Verify verifies the cryptographic signature of the LeaseSet2.
//
// Per the I2P specification, the signature for a LeaseSet2 is computed over
// the serialised content PREPENDED with a single byte containing the
// DatabaseStore type (0x03). The verified data is:
//
//	[]byte{0x03} + Bytes()[:len(Bytes()) - signatureLength]
//
// If HasOfflineKeys() is true, the signature is verified against the transient
// signing public key from the OfflineSignature; otherwise it is verified against
// the Destination's signing public key.
//
// Returns nil if the signature is valid, or an error describing the failure.
func (ls2 *LeaseSet2) Verify() error {
	log.Debug("Verifying LeaseSet2 signature")

	// Serialize the full LeaseSet2 (including the trailing signature)
	fullBytes, err := ls2.Bytes()
	if err != nil {
		return oops.Errorf("failed to serialize LeaseSet2 for verification: %w", err)
	}

	// Get the signature bytes and length
	sigBytes := ls2.signature.Bytes()
	sigLen := len(sigBytes)

	if len(fullBytes) < sigLen {
		return oops.Errorf("LeaseSet2 data too short for signature verification")
	}

	// Data to verify: type byte prefix + everything except the trailing signature
	contentBytes := fullBytes[:len(fullBytes)-sigLen]
	dataToVerify := make([]byte, 0, 1+len(contentBytes))
	dataToVerify = append(dataToVerify, LEASESET2_DBSTORE_TYPE)
	dataToVerify = append(dataToVerify, contentBytes...)

	// Determine which signing public key to use for verification
	signingPubKey, err := ls2.signingPublicKeyForVerification()
	if err != nil {
		return oops.Errorf("failed to get signing public key for verification: %w", err)
	}

	// Create verifier and verify
	verifier, err := signingPubKey.NewVerifier()
	if err != nil {
		return oops.Errorf("failed to create verifier: %w", err)
	}

	if err := verifier.Verify(dataToVerify, sigBytes); err != nil {
		log.WithError(err).Warn("LeaseSet2 signature verification failed")
		return oops.Errorf("LeaseSet2 signature verification failed: %w", err)
	}

	log.Debug("LeaseSet2 signature verification succeeded")
	return nil
}

// signingPublicKeyForVerification returns the appropriate signing public key
// for signature verification. If offline keys are present, the transient
// signing public key from the OfflineSignature is constructed and returned.
// Otherwise, the Destination's signing public key is returned.
func (ls2 *LeaseSet2) signingPublicKeyForVerification() (types.SigningPublicKey, error) {
	if ls2.HasOfflineKeys() && ls2.offlineSignature != nil {
		// Use transient signing public key from offline signature
		transientKeyBytes := ls2.offlineSignature.TransientPublicKey()
		transientSigType := ls2.offlineSignature.TransientSigType()
		spk, err := key_certificate.ConstructSigningPublicKeyByType(transientKeyBytes, int(transientSigType))
		if err != nil {
			return nil, oops.Errorf("failed to construct transient signing public key: %w", err)
		}
		return spk, nil
	}

	// Use destination's signing public key
	spk, err := ls2.destination.SigningPublicKey()
	if err != nil {
		return nil, oops.Errorf("failed to get signing public key from Destination: %w", err)
	}
	return spk, nil
}
