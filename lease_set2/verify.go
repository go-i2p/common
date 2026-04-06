// Package lease_set2 implements the I2P LeaseSet2 common data structure
package lease_set2

import (
	rootcommon "github.com/go-i2p/common"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Verify verifies the cryptographic signature of the LeaseSet2.
//
// Per the I2P specification, the signature for a LeaseSet2 is computed over
// the serialised content PREPENDED with a single byte containing the
// DatabaseStore type (0x03). The verified data is:
//
//	[]byte{0x03} + Bytes()[:len(Bytes()) - signatureLength]
//
// If HasOfflineKeys() is true, Verify additionally checks that the offline
// signature authorization chain is valid: the transient signing key must have
// been signed by the Destination's long-term signing private key. Only after
// that chain check passes is the body signature verified against the transient
// key. This prevents a forged transient key from being trusted.
//
// Returns nil if the signature is valid, or an error describing the failure.
func (ls2 *LeaseSet2) Verify() error {
	log.WithFields(logger.Fields{"pkg": "lease_set2", "func": "LeaseSet2.Verify"}).Debug("Verifying LeaseSet2 signature")

	// When offline keys are present, verify the authorization chain first.
	if ls2.HasOfflineKeys() {
		if err := ls2.verifyOfflineSignatureChain(); err != nil {
			return err
		}
	}

	// Serialize the full LeaseSet2 (including the trailing signature)
	fullBytes, err := ls2.Bytes()
	if err != nil {
		return oops.Errorf("failed to serialize LeaseSet2 for verification: %w", err)
	}

	// Determine which signing public key to use for verification
	signingPubKey, err := rootcommon.ResolveSigningPublicKey(
		ls2.HasOfflineKeys(), ls2.offlineSignature, ls2.destination,
	)
	if err != nil {
		return oops.Errorf("failed to get signing public key for verification: %w", err)
	}

	return rootcommon.VerifyLeaseSetSignature(
		LEASESET2_DBSTORE_TYPE, fullBytes, ls2.signature.Bytes(),
		signingPubKey, "LeaseSet2",
	)
}

// verifyOfflineSignatureChain checks that the offline signature's transient key
// was legitimately authorized by the Destination's long-term signing key.
// This prevents an attacker from substituting an arbitrary transient key.
func (ls2 *LeaseSet2) verifyOfflineSignatureChain() error {
	if ls2.offlineSignature == nil {
		return oops.Errorf("OFFLINE_KEYS flag set but offline signature is nil")
	}

	destSigningKey, err := ls2.destination.SigningPublicKey()
	if err != nil {
		return oops.Errorf("failed to get destination signing public key: %w", err)
	}

	valid, err := ls2.offlineSignature.VerifySignature(destSigningKey.Bytes())
	if err != nil {
		return oops.Errorf("offline signature chain verification error: %w", err)
	}
	if !valid {
		return oops.Errorf("offline signature chain invalid: transient key was not signed by destination key")
	}
	return nil
}
