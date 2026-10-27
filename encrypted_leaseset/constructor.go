package encrypted_leaseset

import (
	"crypto/ed25519"

	rootcommon "github.com/go-i2p/common"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
	goi2ped25519 "github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// NewEncryptedLeaseSet creates a spec-compliant EncryptedLeaseSet from raw fields.
//
// Parameters:
//   - sigType: signing key type for the blinded public key (e.g., 7=Ed25519, 11=RedDSA)
//   - blindedPublicKey: the blinded signing public key bytes
//   - published: timestamp in seconds since Unix epoch
//   - expiresOffset: expiration offset in seconds from published (1‑65535)
//   - flags: flag bits (bit 0=offline, bit 1=unpublished, bits 15‑2 must be 0)
//   - offlineSig: optional offline signature (required if flags bit 0 set)
//   - encryptedInnerData: encrypted LeaseSet2 payload
//   - signingKey: the signing private key. For sigType 11 (RedDSA - the form the
//     spec mandates for a blinded key) pass the blinded 32-byte Red25519 scalar
//     a' (red25519.Red25519PrivateKey or a 32-byte []byte), or an Ed25519 private
//     key, which is converted with the spec's CONVERT_ED25519_PRIVATE. For sigType
//     7 (Ed25519, the unblinded case) pass the 64-byte expanded key ([64]byte,
//     ed25519.PrivateKey, *Ed25519PrivateKey, or 64-byte []byte).
//
// The signature is computed over: 0x05 || serialized_content (without the
// signature itself), with no pre-hashing. Signing is delegated to
// github.com/go-i2p/crypto: the randomized Red25519 signer for type 11, the
// Ed25519 signer for type 7.
func NewEncryptedLeaseSet(
	sigType uint16,
	blindedPublicKey []byte,
	published uint32,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	encryptedInnerData []byte,
	signingKey interface{},
) (*EncryptedLeaseSet, error) {
	log.WithFields(logger.Fields{"pkg": "encrypted_leaseset", "func": "NewEncryptedLeaseSet"}).Debug("Creating new EncryptedLeaseSet")

	if err := validateInputs(sigType, blindedPublicKey, expiresOffset, flags, offlineSig, encryptedInnerData); err != nil {
		return nil, err
	}

	els := &EncryptedLeaseSet{
		sigType:            sigType,
		blindedPublicKey:   blindedPublicKey,
		published:          published,
		expires:            expiresOffset,
		flags:              flags,
		offlineSignature:   offlineSig,
		innerLength:        uint16(len(encryptedInnerData)),
		encryptedInnerData: encryptedInnerData,
	}

	if err := signEncryptedLeaseSet(els, sigType, offlineSig, signingKey); err != nil {
		return nil, err
	}

	logEncryptedLeaseSetCreation(els)
	return els, nil
}

// signEncryptedLeaseSet serializes and signs the EncryptedLeaseSet data.
func signEncryptedLeaseSet(els *EncryptedLeaseSet, sigType uint16, offlineSig *offline_signature.OfflineSignature, signingKey interface{}) error {
	dataToSign, err := els.dataForSigning()
	if err != nil {
		return err
	}
	signingSigType := sigType
	if offlineSig != nil {
		signingSigType = offlineSig.TransientSigType()
	}
	signature, err := createSignature(signingKey, dataToSign, signingSigType)
	if err != nil {
		return err
	}
	els.signature = signature
	return nil
}

// logEncryptedLeaseSetCreation logs the successful creation of an EncryptedLeaseSet.
func logEncryptedLeaseSetCreation(els *EncryptedLeaseSet) {
	log.WithFields(logger.Fields{
		"pkg":            "encrypted_leaseset",
		"func":           "logEncryptedLeaseSetCreation",
		"sig_type":       els.sigType,
		"inner_length":   els.innerLength,
		"has_offline":    els.HasOfflineKeys(),
		"published":      els.published,
		"expires_offset": els.expires,
	}).Debug("Successfully created EncryptedLeaseSet")
}

// NewEncryptedLeaseSetFromDestination creates an EncryptedLeaseSet from a blinded Destination.
// This convenience function extracts the sig_type and blinded signing public key
// from the Destination, then delegates to NewEncryptedLeaseSet.
func NewEncryptedLeaseSetFromDestination(
	blindedDest destination.Destination,
	published uint32,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	encryptedInnerData []byte,
	signingKey interface{},
) (*EncryptedLeaseSet, error) {
	sigType := uint16(blindedDest.KeyCertificate.SigningPublicKeyType())

	spk, err := blindedDest.SigningPublicKey()
	if err != nil {
		return nil, oops.Errorf("failed to extract signing public key from destination: %w", err)
	}

	return NewEncryptedLeaseSet(
		sigType,
		spk.Bytes(),
		published,
		expiresOffset,
		flags,
		offlineSig,
		encryptedInnerData,
		signingKey,
	)
}

// dataForSigning returns the data that the signature covers:
// 0x05 || content_bytes (everything except the trailing signature).
func (els *EncryptedLeaseSet) dataForSigning() ([]byte, error) {
	content, err := els.bytesWithoutSignature()
	if err != nil {
		return nil, oops.Errorf("failed to serialize for signing: %w", err)
	}
	data := make([]byte, 0, 1+len(content))
	data = append(data, ENCRYPTED_LEASESET_DBSTORE_TYPE)
	data = append(data, content...)
	return data, nil
}

// validateInputs validates all constructor parameters.
func validateInputs(
	sigType uint16,
	blindedPublicKey []byte,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	encryptedInnerData []byte,
) error {
	if err := validateSigTypeAndKeySize(sigType, blindedPublicKey); err != nil {
		return err
	}
	if err := validateConstructorFlags(expiresOffset, flags, offlineSig); err != nil {
		return err
	}
	return validateEncryptedPayload(encryptedInnerData)
}

// validateSigTypeAndKeySize validates the signing key type is Red25519 (11) or
// Ed25519 (7) per spec, and the blinded public key has the correct size.
func validateSigTypeAndKeySize(sigType uint16, blindedPublicKey []byte) error {
	if !isAllowedBlindedSigType(sigType) {
		return oops.Code("invalid_sig_type").
			With("sig_type", sigType).
			Errorf("invalid blinded sig_type %d: spec requires Red25519 (11) or Ed25519 (7)", sigType)
	}
	sizes := key_certificate.SigningKeySizes[int(sigType)]
	if len(blindedPublicKey) != sizes.SigningPublicKeySize {
		return oops.Code("invalid_key_size").
			With("got", len(blindedPublicKey)).
			With("expected", sizes.SigningPublicKeySize).
			Errorf("blinded public key size %d != expected %d for sig_type %d",
				len(blindedPublicKey), sizes.SigningPublicKeySize, sigType)
	}
	return nil
}

// validateConstructorFlags validates the expires offset, reserved flags, and offline
// signature consistency for the EncryptedLeaseSet constructor.
func validateConstructorFlags(expiresOffset, flags uint16, offlineSig *offline_signature.OfflineSignature) error {
	if expiresOffset == 0 {
		return oops.Code("zero_expires").
			Errorf("expires offset cannot be zero")
	}
	if flags&ENCRYPTED_LEASESET_RESERVED_FLAGS_MASK != 0 {
		return oops.Code("reserved_flags_set").
			Errorf("reserved flag bits 15‑2 must be zero, got 0x%04x", flags)
	}
	if (flags&ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS) != 0 && offlineSig == nil {
		return oops.Code("missing_offline_sig").
			Errorf("OFFLINE_KEYS flag set but no offline signature provided")
	}
	if (flags&ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS) == 0 && offlineSig != nil {
		return oops.Code("unexpected_offline_sig").
			Errorf("offline signature provided but OFFLINE_KEYS flag not set")
	}
	return validateTransientSigType(offlineSig)
}

// validateTransientSigType enforces the offline-key restriction for encrypted
// lease sets. Per https://geti2p.net/spec/encryptedleaseset §"Blinding - Goals":
//
//	"If the signing public key is offline, the transient signing public key must
//	 also be Ed25519"
//
// so a blinded/encrypted lease set may not carry a RedDSA (or any other)
// transient key. nil offlineSig means no offline keys are in use and is valid.
func validateTransientSigType(offlineSig *offline_signature.OfflineSignature) error {
	if offlineSig == nil {
		return nil
	}
	if got := offlineSig.TransientSigType(); got != key_certificate.KEYCERT_SIGN_ED25519 {
		return oops.Code("invalid_transient_sig_type").
			With("transient_sig_type", got).
			Errorf("encrypted lease set offline transient signing key must be Ed25519 (7), got %d", got)
	}
	return nil
}

// validateEncryptedPayload validates that the encrypted inner data is present,
// meets the minimum size requirement, and fits the 2-byte "len" field. The
// spec bounds "len" only from below ("1 <= len <= max TBD"), so the upper
// bound here is the field width itself: anything larger cannot be represented
// without wrapping the length byte pair while still serializing the full
// payload, which would produce an unparseable structure.
func validateEncryptedPayload(encryptedInnerData []byte) error {
	if len(encryptedInnerData) == 0 {
		return oops.Code("empty_encrypted_data").
			Errorf("encrypted inner data cannot be empty")
	}
	if len(encryptedInnerData) < ENCRYPTED_LEASESET_MIN_ENCRYPTED_SIZE {
		return oops.Code("encrypted_data_too_short").
			With("size", len(encryptedInnerData)).
			With("minimum", ENCRYPTED_LEASESET_MIN_ENCRYPTED_SIZE).
			Errorf("encrypted inner data size %d < minimum %d",
				len(encryptedInnerData), ENCRYPTED_LEASESET_MIN_ENCRYPTED_SIZE)
	}
	if len(encryptedInnerData) > ENCRYPTED_LEASESET_MAX_INNER_LENGTH {
		return oops.Code("encrypted_data_too_large").
			With("size", len(encryptedInnerData)).
			With("maximum", ENCRYPTED_LEASESET_MAX_INNER_LENGTH).
			Errorf("encrypted inner data size %d exceeds the 2-byte len field maximum %d",
				len(encryptedInnerData), ENCRYPTED_LEASESET_MAX_INNER_LENGTH)
	}
	return nil
}

// createSignature signs the EncryptedLeaseSet data with the key type the spec
// requires for the outer signature.
//
// Per encryptedleaseset.md §Signing, "For signing of the encrypted leaseset, we
// use Red25519 based on RedDSA to sign and verify with blinded keys", and the
// blinded signing key "will always be type 11". So a type 11 signature MUST use
// the randomized Red25519 scheme from github.com/go-i2p/crypto/red25519: SIGN
// begins "T = 80 random bytes", which is what gives blinded leasesets their
// unlinkability. A deterministic Ed25519 signature over the same key would let
// an observer correlate re-publications, defeating the blinding.
//
// Type 7 (Ed25519) is still accepted for the unblinded-leaseset case described
// in the same section ("The unblinded leaseset is signed by the unblinded
// Ed25519 or Red25519 signing private key ... as usual").
//
// Accepted signingKey forms:
//   - red25519.Red25519PrivateKey (or 32-byte []byte) — the blinded scalar a',
//     used directly for type 11.
//   - ed25519.PrivateKey / [64]byte / 64-byte []byte — converted with the spec's
//     CONVERT_ED25519_PRIVATE for type 11, or used directly for type 7.
//   - *ed25519.Ed25519PrivateKey (go-i2p/crypto) — used directly for type 7.
//
// Do NOT pre-hash: both Ed25519 and Red25519 are PureEdDSA schemes and sign the
// message directly.
func createSignature(signingKey interface{}, data []byte, sigType uint16) (sig.Signature, error) {
	switch sigType {
	case uint16(sig.SIGNATURE_TYPE_REDDSA_SHA512_ED25519):
		signatureBytes, err := rootcommon.SignLeaseSetData(signingKey, data, sigType)
		if err != nil {
			return sig.Signature{}, err
		}
		return sig.NewSignatureFromBytes(signatureBytes, int(sigType))

	case uint16(sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519):
		return createEd25519Signature(signingKey, data, sigType)

	default:
		return sig.Signature{}, oops.Code("unsupported_signature_type").
			With("sig_type", sigType).
			Errorf("encrypted leaseset signing supports only Ed25519 (7) and RedDSA (11), got %d", sigType)
	}
}

// createEd25519Signature signs with Ed25519 for the unblinded (type 7) case.
// The signing is delegated to github.com/go-i2p/crypto/ed25519's signer; this
// package implements no cryptography itself. All accepted key forms are the
// 64-byte expanded Ed25519 private key in one of its in-repo shapes.
func createEd25519Signature(signingKey interface{}, data []byte, sigType uint16) (sig.Signature, error) {
	var raw []byte
	switch key := signingKey.(type) {
	case ed25519.PrivateKey:
		raw = key
	case [64]byte:
		raw = key[:]
	case *goi2ped25519.Ed25519PrivateKey:
		raw = key.Bytes()
	case []byte:
		if len(key) != ed25519.PrivateKeySize {
			return sig.Signature{}, oops.Code("invalid_key_length").
				With("length", len(key)).
				Errorf("byte slice signing key must be %d bytes for Ed25519, got %d",
					ed25519.PrivateKeySize, len(key))
		}
		raw = key
	default:
		return sig.Signature{}, oops.Code("unsupported_key_type").
			Errorf("unsupported signing key type: %T", signingKey)
	}

	priv, err := goi2ped25519.NewEd25519PrivateKey(raw)
	if err != nil {
		return sig.Signature{}, oops.Wrapf(err, "failed to construct Ed25519 signing key")
	}
	signer, err := priv.NewSigner()
	if err != nil {
		return sig.Signature{}, oops.Wrapf(err, "failed to create Ed25519 signer")
	}
	signatureBytes, err := signer.Sign(data)
	if err != nil {
		return sig.Signature{}, oops.Wrapf(err, "Ed25519 signing failed")
	}
	return sig.NewSignatureFromBytes(signatureBytes, int(sigType))
}
