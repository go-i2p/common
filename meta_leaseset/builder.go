// Package meta_leaseset implements the I2P MetaLeaseSet common data structure
package meta_leaseset

import (
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

	if err := validateAllMetaLeaseSetInputs(dest, flags, offlineSig, options, entries); err != nil {
		return MetaLeaseSet{}, err
	}

	dataToSign, err := serializeMetaLeaseSetForSigning(
		dest, published, expiresOffset, flags,
		offlineSig, options, entries, revocations,
	)
	if err != nil {
		return MetaLeaseSet{}, err
	}

	signature, err := signMetaLeaseSetData(dest, offlineSig, signingKey, dataToSign)
	if err != nil {
		return MetaLeaseSet{}, err
	}

	mls := assembleMetaLeaseSet(dest, published, expiresOffset, flags, offlineSig, options, entries, revocations, signature)
	logMetaLeaseSetCreation(mls)
	return mls, nil
}

// validateAllMetaLeaseSetInputs validates all inputs including options sorting for MetaLeaseSet creation.
func validateAllMetaLeaseSetInputs(
	dest destination.Destination,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	options common.Mapping,
	entries []MetaLeaseSetEntry,
) error {
	if err := validateNewMetaLeaseSetInputs(dest, flags, offlineSig, entries); err != nil {
		return err
	}
	return validateOptionsSorted(options)
}

// signMetaLeaseSetData determines the signature type and signs the serialized data.
func signMetaLeaseSetData(dest destination.Destination, offlineSig *offline_signature.OfflineSignature, signingKey interface{}, dataToSign []byte) (sig.Signature, error) {
	sigType := rootcommon.DetermineSignatureType(dest.KeyCertificate.SigningPublicKeyType(), offlineSig)
	return rootcommon.CreateLeaseSetSignature(signingKey, dataToSign, sigType, rootcommon.SignLeaseSetData)
}

// assembleMetaLeaseSet constructs the MetaLeaseSet struct from its validated and signed components.
func assembleMetaLeaseSet(
	dest destination.Destination,
	published uint32,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	options common.Mapping,
	entries []MetaLeaseSetEntry,
	revocations [][32]byte,
	signature sig.Signature,
) MetaLeaseSet {
	return MetaLeaseSet{
		destination: dest, published: published, expires: expiresOffset,
		flags: flags, offlineSignature: offlineSig, options: options,
		numEntries: uint8(len(entries)), entries: entries,
		numRevocations: uint8(len(revocations)), revocations: revocations,
		signature: signature,
	}
}

// logMetaLeaseSetCreation logs the successful creation of a MetaLeaseSet.
func logMetaLeaseSetCreation(mls MetaLeaseSet) {
	log.WithFields(logger.Fields{
		"num_entries":      len(mls.entries),
		"num_revocations":  len(mls.revocations),
		"has_offline_keys": mls.HasOfflineKeys(),
		"published":        mls.published,
		"expires_offset":   mls.expires,
	}).Debug("Successfully created MetaLeaseSet")
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
	return rootcommon.PrependLeaseSetTypeByte(META_LEASESET_DBSTORE_TYPE, content), nil
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
