package encrypted_leaseset

import (
	"crypto/ed25519"
	"crypto/sha512"

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
//   - signingKey: Ed25519 private key ([64]byte, *Ed25519PrivateKey, or 64-byte []byte)
//
// The signature is computed over: 0x05 || serialized_content (without the signature itself),
// using standard Ed25519 (no pre-hashing).
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
	log.Debug("Creating new EncryptedLeaseSet")

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

	// Serialize content for signing: type_byte + all_fields_except_signature
	dataToSign, err := els.dataForSigning()
	if err != nil {
		return nil, err
	}

	// Determine which sig type to use for signing
	signingSigType := sigType
	if offlineSig != nil {
		signingSigType = offlineSig.TransientSigType()
	}

	// Sign (standard Ed25519, no pre-hashing)
	signature, err := createSignature(signingKey, dataToSign, signingSigType)
	if err != nil {
		return nil, err
	}
	els.signature = signature

	log.WithFields(logger.Fields{
		"sig_type":       sigType,
		"inner_length":   els.innerLength,
		"has_offline":    els.HasOfflineKeys(),
		"published":      published,
		"expires_offset": expiresOffset,
	}).Debug("Successfully created EncryptedLeaseSet")

	return els, nil
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
	// Validate sig_type
	sizes, ok := key_certificate.SigningKeySizes[int(sigType)]
	if !ok {
		return oops.Code("unknown_sig_type").
			With("sig_type", sigType).
			Errorf("unknown signing key type: %d", sigType)
	}

	// Validate blinded public key size
	if len(blindedPublicKey) != sizes.SigningPublicKeySize {
		return oops.Code("invalid_key_size").
			With("got", len(blindedPublicKey)).
			With("expected", sizes.SigningPublicKeySize).
			Errorf("blinded public key size %d != expected %d for sig_type %d",
				len(blindedPublicKey), sizes.SigningPublicKeySize, sigType)
	}

	// Validate expires offset
	if expiresOffset == 0 {
		return oops.Code("zero_expires").
			Errorf("expires offset cannot be zero")
	}

	// Validate reserved flags
	if flags&ENCRYPTED_LEASESET_RESERVED_FLAGS_MASK != 0 {
		return oops.Code("reserved_flags_set").
			Errorf("reserved flag bits 15‑2 must be zero, got 0x%04x", flags)
	}

	// Validate offline signature flag consistency
	if (flags&ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS) != 0 && offlineSig == nil {
		return oops.Code("missing_offline_sig").
			Errorf("OFFLINE_KEYS flag set but no offline signature provided")
	}
	if (flags&ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS) == 0 && offlineSig != nil {
		return oops.Code("unexpected_offline_sig").
			Errorf("offline signature provided but OFFLINE_KEYS flag not set")
	}

	// Validate encrypted inner data
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

	return nil
}

// createSignature signs data using Ed25519 with SHA-512 pre-hashing, matching
// the go-i2p/crypto library's convention (Ed25519Signer.Sign pre-hashes with
// SHA-512 before calling ed25519.Sign; Ed25519Verifier.Verify does the same).
// Supports ed25519.PrivateKey, [64]byte, *Ed25519PrivateKey, and 64-byte []byte key types.
func createSignature(signingKey interface{}, data []byte, sigType uint16) (sig.Signature, error) {
	// Pre-hash with SHA-512 to match go-i2p/crypto Ed25519 convention
	h := sha512.Sum512(data)

	switch key := signingKey.(type) {
	case ed25519.PrivateKey:
		signatureBytes := ed25519.Sign(key, h[:])
		return sig.NewSignatureFromBytes(signatureBytes, int(sigType))

	case [64]byte:
		signatureBytes := ed25519.Sign(key[:], h[:])
		return sig.NewSignatureFromBytes(signatureBytes, int(sigType))

	case *goi2ped25519.Ed25519PrivateKey:
		signatureBytes := ed25519.Sign(key.Bytes(), h[:])
		return sig.NewSignatureFromBytes(signatureBytes, int(sigType))

	case []byte:
		if len(key) == ed25519.PrivateKeySize {
			signatureBytes := ed25519.Sign(key, h[:])
			return sig.NewSignatureFromBytes(signatureBytes, int(sigType))
		}
		return sig.Signature{}, oops.Code("invalid_key_length").
			With("length", len(key)).
			Errorf("byte slice signing key must be %d bytes for Ed25519, got %d",
				ed25519.PrivateKeySize, len(key))

	default:
		return sig.Signature{}, oops.Code("unsupported_key_type").
			Errorf("unsupported signing key type: %T", signingKey)
	}
}
