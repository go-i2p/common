// Package meta_leaseset implements the I2P MetaLeaseSet common data structure
package meta_leaseset

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
	rootcommon "github.com/go-i2p/common"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// NewMetaLeaseSet constructs a new MetaLeaseSet, signs it with the provided
// signing key, and returns the assembled structure. The signing key must be
// an ed25519.PrivateKey or a []byte of ed25519.PrivateKeySize length.
//
// The options Mapping must already be sorted by key for signature invariance,
// per the I2P specification.
//
// Supported signature types: Ed25519 (7), Ed25519ph (8), RedDSA (11).
func NewMetaLeaseSet(
	dest destination.Destination,
	published uint32,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	options common.Mapping,
	entries []MetaLeaseSetEntry,
	revocations [][32]byte,
	signingKey interface{},
) (MetaLeaseSet, error) {
	log.Debug("Creating new MetaLeaseSet")

	if err := validateNewMetaLeaseSetInputs(dest, flags, offlineSig, entries); err != nil {
		return MetaLeaseSet{}, err
	}

	if err := validateOptionsSorted(options); err != nil {
		return MetaLeaseSet{}, err
	}

	// Serialize content for signing (prepended with DB store type byte)
	dataToSign, err := serializeMetaLeaseSetForSigning(
		dest, published, expiresOffset, flags,
		offlineSig, options, entries, revocations,
	)
	if err != nil {
		return MetaLeaseSet{}, err
	}

	sigType := determineSignatureType(dest, offlineSig)
	signature, err := createMetaLeaseSetSignature(signingKey, dataToSign, sigType)
	if err != nil {
		return MetaLeaseSet{}, err
	}

	mls := MetaLeaseSet{
		destination:      dest,
		published:        published,
		expires:          expiresOffset,
		flags:            flags,
		offlineSignature: offlineSig,
		options:          options,
		numEntries:       uint8(len(entries)),
		entries:          entries,
		numRevocations:   uint8(len(revocations)),
		revocations:      revocations,
		signature:        signature,
	}

	log.WithFields(logger.Fields{
		"num_entries":      len(entries),
		"num_revocations":  len(revocations),
		"has_offline_keys": mls.HasOfflineKeys(),
		"published":        published,
		"expires_offset":   expiresOffset,
	}).Debug("Successfully created MetaLeaseSet")

	return mls, nil
}

// validateNewMetaLeaseSetInputs validates all input parameters for MetaLeaseSet creation.
func validateNewMetaLeaseSetInputs(
	dest destination.Destination,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	entries []MetaLeaseSetEntry,
) error {
	if err := validateNewDestinationSize(dest); err != nil {
		return err
	}
	if err := validateNewOfflineSignatureFlags(flags, offlineSig); err != nil {
		return err
	}
	return validateNewEntryInputs(entries)
}

// validateNewDestinationSize checks that the destination can serialize to a valid size.
func validateNewDestinationSize(dest destination.Destination) error {
	destBytes, err := dest.Bytes()
	if err != nil {
		return oops.Errorf("invalid destination: %w", err)
	}
	if len(destBytes) < META_LEASESET_MIN_DESTINATION_SIZE {
		return oops.
			Code("invalid_destination_size").
			With("size", len(destBytes)).
			With("minimum", META_LEASESET_MIN_DESTINATION_SIZE).
			Errorf("destination size must be at least %d bytes", META_LEASESET_MIN_DESTINATION_SIZE)
	}
	return nil
}

// validateNewOfflineSignatureFlags validates consistency between flags and offline signature.
func validateNewOfflineSignatureFlags(flags uint16, offlineSig *offline_signature.OfflineSignature) error {
	if (flags&META_LEASESET_FLAG_OFFLINE_KEYS) != 0 && offlineSig == nil {
		return oops.
			Code("missing_offline_signature").
			Errorf("OFFLINE_KEYS flag set but no offline signature provided")
	}
	if (flags&META_LEASESET_FLAG_OFFLINE_KEYS) == 0 && offlineSig != nil {
		return oops.
			Code("unexpected_offline_signature").
			Errorf("offline signature provided but OFFLINE_KEYS flag not set")
	}
	return nil
}

// validateNewEntryInputs validates the entry count is within spec limits.
func validateNewEntryInputs(entries []MetaLeaseSetEntry) error {
	if len(entries) < META_LEASESET_MIN_ENTRIES {
		return oops.
			Code("no_entries").
			Errorf("at least %d entry is required per I2P specification", META_LEASESET_MIN_ENTRIES)
	}
	if len(entries) > META_LEASESET_MAX_ENTRIES {
		return oops.
			Code("too_many_entries").
			With("max_allowed", META_LEASESET_MAX_ENTRIES).
			Errorf("too many entries: %d exceeds maximum %d", len(entries), META_LEASESET_MAX_ENTRIES)
	}
	return nil
}

// validateOptionsSorted checks that the options mapping keys are in sorted order.
func validateOptionsSorted(options common.Mapping) error {
	vals := options.Values()
	for i := 1; i < len(vals); i++ {
		prevKey, err := vals[i-1][0].Data()
		if err != nil {
			return oops.Errorf("invalid option key at index %d: %w", i-1, err)
		}
		curKey, err := vals[i][0].Data()
		if err != nil {
			return oops.Errorf("invalid option key at index %d: %w", i, err)
		}
		if curKey < prevKey {
			return oops.
				Code("options_not_sorted").
				Errorf("options keys not sorted: %q appears before %q", prevKey, curKey)
		}
	}
	return nil
}

// serializeMetaLeaseSetForSigning serializes the MetaLeaseSet content for signing.
// Per spec, the signature covers all content prepended with the DB store type byte (0x07).
func serializeMetaLeaseSetForSigning(
	dest destination.Destination,
	published uint32,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	options common.Mapping,
	entries []MetaLeaseSetEntry,
	revocations [][32]byte,
) ([]byte, error) {
	content, err := serializeMetaLeaseSetContent(
		dest, published, expiresOffset, flags,
		offlineSig, options, entries, revocations,
	)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 1+len(content))
	data = append(data, META_LEASESET_DBSTORE_TYPE)
	data = append(data, content...)
	return data, nil
}

// serializeMetaLeaseSetContent serializes all MetaLeaseSet fields except the signature.
func serializeMetaLeaseSetContent(
	dest destination.Destination,
	published uint32,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	options common.Mapping,
	entries []MetaLeaseSetEntry,
	revocations [][32]byte,
) ([]byte, error) {
	// Serialize the common header (dest, published, expires, flags, offlineSig, options)
	data, err := rootcommon.SerializeLeaseSetHeader(dest, published, expiresOffset, flags, offlineSig, options)
	if err != nil {
		return nil, err
	}

	data = append(data, byte(len(entries)))
	for _, entry := range entries {
		entryBytes, err := entry.Bytes()
		if err != nil {
			return nil, oops.Wrapf(err, "failed to serialize entry")
		}
		data = append(data, entryBytes...)
	}

	data = append(data, byte(len(revocations)))
	for _, hash := range revocations {
		data = append(data, hash[:]...)
	}

	return data, nil
}

// determineSignatureType returns the signature type to use for signing.
func determineSignatureType(dest destination.Destination, offlineSig *offline_signature.OfflineSignature) uint16 {
	return rootcommon.DetermineSignatureType(dest.KeyCertificate.SigningPublicKeyType(), offlineSig)
}

// createMetaLeaseSetSignature signs the MetaLeaseSet data with the provided key.
// Supported signing types: Ed25519 (7), Ed25519ph (8), RedDSA (11).
func createMetaLeaseSetSignature(signingKey interface{}, data []byte, sigType uint16) (sig.Signature, error) {
	sigSize := offline_signature.SignatureSize(sigType)
	if sigSize == 0 {
		return sig.Signature{}, oops.
			Code("unknown_signature_type").
			With("signature_type", sigType).
			Errorf("unknown or unsupported signature type: %d", sigType)
	}

	signatureBytes, err := signMetaLeaseSetData(signingKey, data, sigType)
	if err != nil {
		return sig.Signature{}, err
	}

	signature, err := sig.NewSignatureFromBytes(signatureBytes, int(sigType))
	if err != nil {
		return sig.Signature{}, oops.Errorf("failed to create signature: %w", err)
	}

	return signature, nil
}

// signMetaLeaseSetData performs the cryptographic signing operation.
func signMetaLeaseSetData(signingKey interface{}, data []byte, sigType uint16) ([]byte, error) {
	privKey, err := extractPrivateKey(signingKey)
	if err != nil {
		return nil, err
	}

	switch sigType {
	case uint16(sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519):
		return ed25519.Sign(privKey, data), nil
	case uint16(sig.SIGNATURE_TYPE_REDDSA_SHA512_ED25519):
		return signMetaRedDSA(privKey, data)
	case uint16(sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH):
		return signMetaEd25519ph(privKey, data)
	default:
		return nil, oops.Errorf(
			"signing not implemented for signature type %d (modern crypto only: Ed25519, Ed25519ph, RedDSA)",
			sigType,
		)
	}
}

// extractPrivateKey extracts an ed25519.PrivateKey from the signing key parameter.
func extractPrivateKey(signingKey interface{}) (ed25519.PrivateKey, error) {
	switch key := signingKey.(type) {
	case ed25519.PrivateKey:
		return key, nil
	case []byte:
		if len(key) != ed25519.PrivateKeySize {
			return nil, oops.Errorf("invalid signing key length: got %d, expected %d", len(key), ed25519.PrivateKeySize)
		}
		return ed25519.PrivateKey(key), nil
	case nil:
		return nil, oops.Errorf("signing key is nil")
	default:
		return nil, oops.Errorf("unsupported signing key type: %T (expected ed25519.PrivateKey)", signingKey)
	}
}

// signMetaRedDSA signs data using Red25519 (RedDSA) with randomized nonces.
func signMetaRedDSA(privKey ed25519.PrivateKey, data []byte) ([]byte, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, oops.Errorf("RedDSA: invalid private key size: %d", len(privKey))
	}
	expanded := sha512.Sum512(privKey[:32])
	expanded[0] &= 248
	expanded[31] &= 63
	expanded[31] |= 64

	scalar, err := edwards25519.NewScalar().SetBytesWithClamping(expanded[:32])
	if err != nil {
		return nil, oops.Errorf("RedDSA: failed to set scalar: %w", err)
	}

	pubPoint := edwards25519.NewGeneratorPoint().ScalarBaseMult(scalar)
	pubBytes := pubPoint.Bytes()

	msgHash := sha512.Sum512(append(expanded[32:], data...))
	rScalar, err := edwards25519.NewScalar().SetUniformBytes(msgHash[:])
	if err != nil {
		return nil, oops.Errorf("RedDSA: failed to compute r scalar: %w", err)
	}

	rPoint := edwards25519.NewGeneratorPoint().ScalarBaseMult(rScalar)
	rBytes := rPoint.Bytes()

	kHash := sha512.Sum512(append(append(rBytes, pubBytes...), data...))
	kScalar, err := edwards25519.NewScalar().SetUniformBytes(kHash[:])
	if err != nil {
		return nil, oops.Errorf("RedDSA: failed to compute k scalar: %w", err)
	}

	sScalar := edwards25519.NewScalar().MultiplyAdd(kScalar, scalar, rScalar)

	var result [64]byte
	copy(result[:32], rBytes)
	copy(result[32:], sScalar.Bytes())
	return result[:], nil
}

// signMetaEd25519ph signs data using Ed25519ph (pre-hashed).
func signMetaEd25519ph(privKey ed25519.PrivateKey, data []byte) ([]byte, error) {
	preHash := sha512.Sum512(data)
	return ed25519.Sign(privKey, preHash[:]), nil
}
