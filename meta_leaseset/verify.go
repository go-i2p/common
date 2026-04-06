// Package meta_leaseset implements the I2P MetaLeaseSet common data structure
package meta_leaseset

import (
	rootcommon "github.com/go-i2p/common"
	"github.com/go-i2p/logger"
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
	log.WithFields(logger.Fields{"pkg": "meta_leaseset", "func": "MetaLeaseSet.Verify"}).Debug("Verifying MetaLeaseSet signature")

	// Serialize the full MetaLeaseSet (including the trailing signature)
	fullBytes, err := mls.Bytes()
	if err != nil {
		return oops.Errorf("failed to serialize MetaLeaseSet for verification: %w", err)
	}

	// Determine which signing public key to use for verification
	signingPubKey, err := rootcommon.ResolveSigningPublicKey(
		mls.HasOfflineKeys(), mls.offlineSignature, mls.destination,
	)
	if err != nil {
		return oops.Errorf("failed to get signing public key for verification: %w", err)
	}

	return rootcommon.VerifyLeaseSetSignature(
		META_LEASESET_DBSTORE_TYPE, fullBytes, mls.signature.Bytes(),
		signingPubKey, "MetaLeaseSet",
	)
}
