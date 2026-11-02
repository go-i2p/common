package encrypted_leaseset

import (
	rootcommon "github.com/go-i2p/common"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Verify verifies the cryptographic signature of the EncryptedLeaseSet.
//
// Per the I2P specification, the signature covers: 0x05 || content_without_signature.
// The signing public key is the blinded public key, or the transient key if offline
// signatures are present.
//
// When the offline-keys flag is set, the offline signature is verified FIRST
// against the blinded public key, and must not be expired. The encrypted
// leaseset spec is explicit that the offline signature is "Over expires
// timestamp, transient sig type, and transient public key. Verified with the
// blinded public key." Without that check an attacker could pick any transient
// key, fill the offline signature field with arbitrary bytes, sign the
// structure with the chosen key, and have it verify as any blinded identity.
func (els *EncryptedLeaseSet) Verify() error {
	log.WithFields(logger.Fields{"pkg": "encrypted_leaseset", "func": "EncryptedLeaseSet.Verify"}).Debug("Verifying EncryptedLeaseSet signature")

	// Verify the offline signature authorization chain before trusting the
	// transient key it carries.
	if els.HasOfflineKeys() {
		if err := els.verifyOfflineSignatureChainAgainstBlindedKey(); err != nil {
			return err
		}
	}

	// Serialize: type byte + content without signature
	dataToVerify, err := els.dataForSigning()
	if err != nil {
		return oops.Errorf("failed to serialize for verification: %w", err)
	}

	// Determine the signing public key
	signingPubKey, err := els.signingPublicKeyForVerification()
	if err != nil {
		return oops.Errorf("failed to get signing public key: %w", err)
	}

	return rootcommon.VerifySignatureData(dataToVerify, els.signature.Bytes(), els.signature.Type(), signingPubKey, "EncryptedLeaseSet")
}

// verifyOfflineSignatureChainAgainstBlindedKey checks that the offline
// signature's transient key was legitimately authorized by the blinded signing
// public key carried in this structure, and that it has not expired. Per the
// encrypted leaseset spec, the offline signature is verified with the blinded
// public key (not the unblinded destination key, which is never present in the
// published structure).
func (els *EncryptedLeaseSet) verifyOfflineSignatureChainAgainstBlindedKey() error {
	if els.offlineSignature == nil {
		return oops.Errorf("EncryptedLeaseSet: OFFLINE_KEYS flag set but offline signature is nil")
	}
	return rootcommon.VerifyOfflineSignatureChain(
		els.offlineSignature, els.blindedPublicKey, "EncryptedLeaseSet",
	)
}

// signingPublicKeyForVerification returns the appropriate signing public key
// for signature verification. Uses the transient key from OfflineSignature if
// present, otherwise constructs a key from sigType + blindedPublicKey.
//
// SECURITY: callers MUST verify the offline signature chain before trusting the
// transient key returned here.
func (els *EncryptedLeaseSet) signingPublicKeyForVerification() (types.SigningPublicKey, error) {
	if els.HasOfflineKeys() && els.offlineSignature != nil {
		transientKeyBytes := els.offlineSignature.TransientPublicKey()
		transientSigType := els.offlineSignature.TransientSigType()
		spk, err := key_certificate.ConstructSigningPublicKeyByType(
			transientKeyBytes, int(transientSigType),
		)
		if err != nil {
			return nil, oops.Errorf("failed to construct transient signing public key: %w", err)
		}
		return spk, nil
	}

	// Construct from sigType + blindedPublicKey
	spk, err := key_certificate.ConstructSigningPublicKeyByType(
		els.blindedPublicKey, int(els.sigType),
	)
	if err != nil {
		return nil, oops.Errorf("failed to construct blinded signing public key: %w", err)
	}
	return spk, nil
}
