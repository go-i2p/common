// Package lease_set2 implements the I2P LeaseSet2 common data structure
package lease_set2

import (
	"encoding/binary"
	"sort"
	"time"

	rootcommon "github.com/go-i2p/common"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ApplyCommonFields stores the parsed common header fields into the LeaseSet2,
// satisfying the rootcommon.LeaseSetFieldApplier interface to eliminate
// duplicated field assignment code shared with MetaLeaseSet.
func (ls2 *LeaseSet2) ApplyCommonFields(fields rootcommon.LeaseSetCommonFields) {
	ls2.destination = fields.Destination
	ls2.published = fields.Published
	ls2.expires = fields.Expires
	ls2.flags = fields.Flags
	ls2.offlineSignature = fields.OfflineSignature
	ls2.options = fields.Options
}

// Destination returns the destination identity associated with this LeaseSet2.
// The destination contains the signing and encryption public keys for the service.
func (ls2 *LeaseSet2) Destination() destination.Destination {
	return ls2.destination
}

// Published returns the published timestamp as a uint32 (seconds since Unix epoch).
// This timestamp indicates when the LeaseSet2 was created/published.
func (ls2 *LeaseSet2) Published() uint32 {
	return ls2.published
}

// PublishedTime returns the published timestamp as a Go time.Time value.
// Converts the 4-byte second timestamp to time.Time in UTC timezone.
func (ls2 *LeaseSet2) PublishedTime() time.Time {
	return time.Unix(int64(ls2.published), 0).UTC()
}

// Expires returns the expiration offset in seconds from the published timestamp.
// The actual expiration time is Published() + Expires().
func (ls2 *LeaseSet2) Expires() uint16 {
	return ls2.expires
}

// ExpirationTime returns the absolute expiration time as a Go time.Time value.
// This is calculated as PublishedTime() + Expires() seconds.
func (ls2 *LeaseSet2) ExpirationTime() time.Time {
	return ls2.PublishedTime().Add(time.Duration(ls2.expires) * time.Second)
}

// IsExpired checks if the LeaseSet2 has expired based on the current time.
// Returns true if the current time is after the expiration time.
func (ls2 *LeaseSet2) IsExpired() bool {
	return time.Now().After(ls2.ExpirationTime())
}

// Flags returns the raw flags value (2 bytes).
// Use HasOfflineKeys(), IsUnpublished(), IsBlinded() for flag checking.
func (ls2 *LeaseSet2) Flags() uint16 {
	return ls2.flags
}

// HasOfflineKeys returns true if the offline signature flag is set (bit 0).
// When true, the OfflineSignature field will be populated.
func (ls2 *LeaseSet2) HasOfflineKeys() bool {
	return (ls2.flags & LEASESET2_FLAG_OFFLINE_KEYS) != 0
}

// IsUnpublished returns true if the unpublished flag is set (bit 1).
// Unpublished leasesets should not be flooded or published to the network database.
func (ls2 *LeaseSet2) IsUnpublished() bool {
	return (ls2.flags & LEASESET2_FLAG_UNPUBLISHED) != 0
}

// IsBlinded returns true if the blinded flag is set (bit 2).
// When set, this unencrypted leaseset will be blinded and encrypted when published.
// Introduced in I2P version 0.9.42.
func (ls2 *LeaseSet2) IsBlinded() bool {
	return (ls2.flags & LEASESET2_FLAG_BLINDED) != 0
}

// OfflineSignature returns the optional offline signature structure.
// Returns nil if HasOfflineKeys() is false.
func (ls2 *LeaseSet2) OfflineSignature() *offline_signature.OfflineSignature {
	return ls2.offlineSignature
}

// Options returns the mapping containing service record options.
// Options are used for DNS-SD style service discovery.
func (ls2 *LeaseSet2) Options() common.Mapping {
	return ls2.options
}

// EncryptionKeys returns the slice of encryption keys.
// Keys are in order of server preference, most-preferred first.
func (ls2 *LeaseSet2) EncryptionKeys() []EncryptionKey {
	return ls2.encryptionKeys
}

// EncryptionKeyCount returns the number of encryption keys in this LeaseSet2.
func (ls2 *LeaseSet2) EncryptionKeyCount() int {
	return len(ls2.encryptionKeys)
}

// Leases returns the slice of Lease2 structures.
func (ls2 *LeaseSet2) Leases() []lease.Lease2 {
	return ls2.leases
}

// LeaseCount returns the number of Lease2 structures in this LeaseSet2.
func (ls2 *LeaseSet2) LeaseCount() int {
	return len(ls2.leases)
}

// Signature returns the signature over the LeaseSet2 data.
// The signature is created by the destination's signing key or the transient key if offline signature is present.
func (ls2 *LeaseSet2) Signature() sig.Signature {
	return ls2.signature
}

// Bytes returns the complete LeaseSet2 structure as a byte array.
// This serializes all components in the proper order according to I2P specification 0.9.67.
//
// The serialization includes:
//  1. Destination (387+ bytes)
//  2. Published timestamp (4 bytes)
//  3. Expires offset (2 bytes)
//  4. Flags (2 bytes)
//  5. Offline signature if present (variable length)
//  6. Options mapping (2+ bytes)
//  7. Encryption keys with count (5+ bytes per key)
//  8. Lease2 structures with count (40 bytes per lease)
//  9. Signature (variable length)
//
// Note: the signature was computed over []byte{LEASESET2_DBSTORE_TYPE} || Bytes()[:len-sigLen],
// i.e. a single 0x03 byte is prepended to all content before signing. External verifiers
// must include this prefix when reconstructing the signed payload.
//
// Returns the serialized LeaseSet2 or error if serialization fails.
func (ls2 *LeaseSet2) Bytes() ([]byte, error) {
	content, err := serializeLeaseSet2Content(
		ls2.destination, ls2.published, ls2.expires, ls2.flags,
		ls2.offlineSignature, ls2.options, ls2.encryptionKeys, ls2.leases,
	)
	if err != nil {
		return nil, err
	}

	// Add signature
	result := content
	result = append(result, ls2.signature.Bytes()...)

	log.WithFields(logger.Fields{
		"pkg":             "lease_set2",
		"func":            "LeaseSet2.Bytes",
		"total_size":      len(result),
		"encryption_keys": len(ls2.encryptionKeys),
		"leases":          len(ls2.leases),
		"has_offline_sig": ls2.offlineSignature != nil,
		"options_count":   len(ls2.options.Values()),
	}).Debug("Serialized LeaseSet2 to bytes")

	return result, nil
}

// ReadLeaseSet2 parses a LeaseSet2 structure from the provided byte slice.
// Returns the parsed LeaseSet2, remaining bytes, and any error encountered.
//
// The parsing process:
//  1. Parse destination (387+ bytes)
//  2. Parse published timestamp (4 bytes)
//  3. Parse expires offset (2 bytes)
//  4. Parse flags (2 bytes)
//  5. If flags bit 0 set, parse offline signature (variable length)
//  6. Parse options mapping (variable length, 2+ bytes)
//  7. Parse encryption keys (1+ keys, variable length)
//  8. Parse Lease2 structures (0+ leases, 40 bytes each)
//  9. Parse signature (variable length based on signature type)
//
// Returns error if:
//   - Data is too short for minimum LeaseSet2 size
//   - Destination parsing fails
//   - Any component parsing fails
//   - Number of encryption keys or leases exceeds maximum allowed
func ReadLeaseSet2(data []byte) (ls2 LeaseSet2, remainder []byte, err error) {
	log.WithFields(logger.Fields{"pkg": "lease_set2", "func": "ReadLeaseSet2"}).Debug("Parsing LeaseSet2 structure")

	// Parse and apply common header fields shared with MetaLeaseSet
	data, err = rootcommon.ParseAndApplyCommonPrefix(&ls2, data, LEASESET2_MIN_SIZE, "LeaseSet2")
	if err != nil {
		return ls2, remainder, err
	}

	// Warn if reserved flag bits (bits 15-3) are set per spec:
	// "Bits 15-3: Reserved, set to 0 for compatibility with future uses."
	reservedMask := uint16(0xFFF8) // bits 15-3
	if ls2.flags&reservedMask != 0 {
		log.WithFields(logger.Fields{
			"pkg":           "lease_set2",
			"func":          "ReadLeaseSet2",
			"flags":         ls2.flags,
			"reserved_bits": ls2.flags & reservedMask,
		}).Warn("LeaseSet2 has non-zero reserved flag bits (bits 15-3 should be 0)")
	}

	// Spec: "If [BLINDED] is set, bit 1 (UNPUBLISHED) should also be set."
	if (ls2.flags&LEASESET2_FLAG_BLINDED) != 0 && (ls2.flags&LEASESET2_FLAG_UNPUBLISHED) == 0 {
		err = oops.
			Code("blinded_requires_unpublished").
			Errorf("BLINDED flag (bit 2) requires UNPUBLISHED flag (bit 1) to also be set")
		log.WithFields(logger.Fields{
			"pkg":   "lease_set2",
			"func":  "ReadLeaseSet2",
			"flags": ls2.flags,
		}).Error(err.Error())
		return ls2, remainder, err
	}

	log.WithFields(logger.Fields{
		"pkg":       "lease_set2",
		"func":      "ReadLeaseSet2",
		"published": ls2.published,
		"expires":   ls2.expires,
		"flags":     ls2.flags,
	}).Debug("Parsed LeaseSet2 header")

	// Spec: "LS2 options MUST be sorted by key, so the signature is invariant."
	if err = validateOptionsSorted(ls2.options); err != nil {
		return ls2, remainder, err
	}

	remainder, err = parseKeysLeasesAndSignature(&ls2, data)
	return ls2, remainder, err
}

// parseKeysLeasesAndSignature parses the encryption keys, lease structures,
// and trailing signature from the remaining LeaseSet2 data.
func parseKeysLeasesAndSignature(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	var err error

	data, err = parseEncryptionKeys(ls2, data)
	if err != nil {
		return nil, err
	}

	data, err = parseLeases(ls2, data)
	if err != nil {
		return nil, err
	}

	return parseSignatureAndFinalize(ls2, data)
}

// warnIfOptionsUnsorted checks if the mapping keys are sorted lexicographically
// and logs a warning if they are not. Per spec: "Options MUST be sorted by key
// for signature invariance."
func warnIfOptionsUnsorted(mapping common.Mapping) {
	vals := mapping.Values()
	if len(vals) <= 1 {
		return
	}
	keys := make([]string, 0, len(vals))
	for _, pair := range vals {
		keyData, err := pair[0].Data()
		if err != nil {
			return // can't check, skip
		}
		keys = append(keys, keyData)
	}
	if !sort.StringsAreSorted(keys) {
		log.WithFields(logger.Fields{"pkg": "lease_set2", "func": "warnIfOptionsUnsorted"}).Warn("LeaseSet2 options mapping keys are not sorted; spec requires sorted keys for signature invariance")
	}
}

// validateOptionsSorted checks that options mapping keys are sorted per spec:
// "LS2 options MUST be sorted by key, so the signature is invariant."
// Returns an error if keys are unsorted. An empty or single-key mapping is always valid.
func validateOptionsSorted(options common.Mapping) error {
	vals := options.Values()
	if len(vals) <= 1 {
		return nil
	}
	keys := make([]string, 0, len(vals))
	for _, pair := range vals {
		keyData, err := pair[0].Data()
		if err != nil {
			continue
		}
		keys = append(keys, keyData)
	}
	if !sort.StringsAreSorted(keys) {
		return oops.Errorf("options mapping keys are not sorted; spec requires sorted keys for signature invariance")
	}
	return nil
}

// parseEncryptionKeys parses the encryption keys from the data.
// Returns remaining data after parsing or error if validation or parsing fails.
func parseEncryptionKeys(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	if len(data) < 1 {
		err := oops.
			Code("missing_encryption_key_count").
			Errorf("insufficient data for encryption key count")
		log.WithFields(logger.Fields{
			"pkg":  "lease_set2",
			"func": "parseEncryptionKeys",
			"at":   "parseEncryptionKeys",
		}).Error(err.Error())
		return nil, err
	}

	numKeys := int(data[0])
	data = data[1:]

	if numKeys < 1 || numKeys > LEASESET2_MAX_ENCRYPTION_KEYS {
		err := oops.
			Code("invalid_encryption_key_count").
			With("num_keys", numKeys).
			With("max_allowed", LEASESET2_MAX_ENCRYPTION_KEYS).
			Errorf("invalid encryption key count: %d (must be 1-%d)", numKeys, LEASESET2_MAX_ENCRYPTION_KEYS)
		log.WithFields(logger.Fields{
			"pkg":      "lease_set2",
			"func":     "parseEncryptionKeys",
			"at":       "parseEncryptionKeys",
			"num_keys": numKeys,
		}).Error(err.Error())
		return nil, err
	}

	ls2.encryptionKeys = make([]EncryptionKey, numKeys)
	for i := 0; i < numKeys; i++ {
		var err error
		data, err = parseSingleEncryptionKey(ls2, i, data)
		if err != nil {
			return nil, err
		}
	}

	return data, nil
}

// parseSingleEncryptionKey parses a single encryption key at the specified index.
// Returns remaining data after parsing or error if validation or parsing fails.
func parseSingleEncryptionKey(ls2 *LeaseSet2, keyIndex int, data []byte) ([]byte, error) {
	if err := validateEncryptionKeyHeaderData(len(data), keyIndex); err != nil {
		return nil, err
	}

	keyType, keyLen, rem := extractEncryptionKeyHeader(data)

	if err := validateEncryptionKeyTypeLength(keyType, keyLen, keyIndex); err != nil {
		return nil, err
	}

	if err := validateEncryptionKeyDataLength(len(rem), keyLen, keyIndex); err != nil {
		return nil, err
	}

	keyData, remainder := extractEncryptionKeyData(rem, keyLen)

	storeEncryptionKey(ls2, keyIndex, keyType, keyLen, keyData)

	return remainder, nil
}

// validateEncryptionKeyHeaderData validates that data has sufficient bytes for key type and length.
// Returns error if data is too short for encryption key header.
func validateEncryptionKeyHeaderData(dataLen, keyIndex int) error {
	requiredSize := LEASESET2_ENCRYPTION_KEY_TYPE_SIZE + LEASESET2_ENCRYPTION_KEY_LENGTH_SIZE
	if dataLen < requiredSize {
		err := oops.
			Code("encryption_key_header_too_short").
			With("key_index", keyIndex).
			With("remaining_length", dataLen).
			Errorf("insufficient data for encryption key %d header", keyIndex)
		log.WithFields(logger.Fields{
			"pkg":       "lease_set2",
			"func":      "validateEncryptionKeyHeaderData",
			"at":        "validateEncryptionKeyHeaderData",
			"key_index": keyIndex,
		}).Error(err.Error())
		return err
	}
	return nil
}

// extractEncryptionKeyHeader extracts the key type and length from data.
// Returns key type, key length, and remaining data after extraction.
func extractEncryptionKeyHeader(data []byte) (uint16, uint16, []byte) {
	keyType := binary.BigEndian.Uint16(data[:LEASESET2_ENCRYPTION_KEY_TYPE_SIZE])
	data = data[LEASESET2_ENCRYPTION_KEY_TYPE_SIZE:]

	keyLen := binary.BigEndian.Uint16(data[:LEASESET2_ENCRYPTION_KEY_LENGTH_SIZE])
	data = data[LEASESET2_ENCRYPTION_KEY_LENGTH_SIZE:]

	return keyType, keyLen, data
}

// validateEncryptionKeyDataLength validates that data has sufficient bytes for key data.
// Returns error if insufficient data remains for the specified key length.
func validateEncryptionKeyDataLength(dataLen int, keyLen uint16, keyIndex int) error {
	if dataLen < int(keyLen) {
		err := oops.
			Code("encryption_key_data_too_short").
			With("key_index", keyIndex).
			With("required_length", keyLen).
			With("remaining_length", dataLen).
			Errorf("insufficient data for encryption key %d data", keyIndex)
		log.WithFields(logger.Fields{
			"pkg":       "lease_set2",
			"func":      "validateEncryptionKeyDataLength",
			"at":        "validateEncryptionKeyDataLength",
			"key_index": keyIndex,
			"key_len":   keyLen,
		}).Error(err.Error())
		return err
	}
	return nil
}

// extractEncryptionKeyData extracts the encryption key data from the byte slice.
// Returns the key data and remaining bytes after extraction.
func extractEncryptionKeyData(data []byte, keyLen uint16) ([]byte, []byte) {
	keyData := make([]byte, keyLen)
	copy(keyData, data[:keyLen])
	data = data[keyLen:]
	return keyData, data
}

// validateEncryptionKeyTypeLength returns an error when the declared keyLen does not
// match the spec-required size for a known encryption key type.
// Per spec: "keylen: Must match the specified length of the encryption type."
func validateEncryptionKeyTypeLength(keyType, keyLen uint16, keyIndex int) error {
	info, ok := key_certificate.CryptoKeySizes[int(keyType)]
	if !ok {
		// Unknown type – allow any length (forward compatibility).
		return nil
	}
	expectedSize := info.CryptoPublicKeySize
	if int(keyLen) != expectedSize {
		err := oops.
			Code("encryption_key_len_type_mismatch").
			With("key_index", keyIndex).
			With("key_type", keyType).
			With("declared_len", keyLen).
			With("expected_len", expectedSize).
			Errorf("encryption key %d: declared keyLen %d does not match expected %d for type %d",
				keyIndex, keyLen, expectedSize, keyType)
		log.WithFields(logger.Fields{
			"pkg":          "lease_set2",
			"func":         "validateEncryptionKeyTypeLength",
			"at":           "validateEncryptionKeyTypeLength",
			"key_index":    keyIndex,
			"key_type":     keyType,
			"declared_len": keyLen,
			"expected_len": expectedSize,
		}).Error(err.Error())
		return err
	}
	return nil
}

// storeEncryptionKey stores the parsed encryption key in the LeaseSet2 structure.
// Logs the parsed key information at debug level.
func storeEncryptionKey(ls2 *LeaseSet2, keyIndex int, keyType, keyLen uint16, keyData []byte) {
	ls2.encryptionKeys[keyIndex] = EncryptionKey{
		KeyType: keyType,
		KeyLen:  keyLen,
		KeyData: keyData,
	}

	log.WithFields(logger.Fields{
		"pkg":       "lease_set2",
		"func":      "storeEncryptionKey",
		"key_index": keyIndex,
		"key_type":  keyType,
		"key_len":   keyLen,
	}).Debug("Parsed encryption key")
}

// parseLeases parses the Lease2 structures from the data.
// Returns remaining data after parsing or error if validation or parsing fails.
// validateLeaseCountData validates that data has at least one byte for lease count.
// Returns error if insufficient data is available.
func validateLeaseCountData(dataLen int) error {
	if dataLen < 1 {
		err := oops.
			Code("missing_lease_count").
			Errorf("insufficient data for lease count")
		log.WithFields(logger.Fields{
			"pkg":  "lease_set2",
			"func": "validateLeaseCountData",
			"at":   "validateLeaseCountData",
		}).Error(err.Error())
		return err
	}
	return nil
}

// validateLeaseCount validates that the lease count is within spec-required limits.
// Returns error if the lease count is 0 (spec requires ≥1) or greater than the maximum.
func validateLeaseCount(numLeases int) error {
	if numLeases < 1 {
		err := oops.
			Code("invalid_lease_count").
			With("num_leases", numLeases).
			Errorf("invalid lease count: %d (spec requires at least 1 lease)", numLeases)
		log.WithFields(logger.Fields{
			"pkg":        "lease_set2",
			"func":       "validateLeaseCount",
			"at":         "validateLeaseCount",
			"num_leases": numLeases,
		}).Error(err.Error())
		return err
	}
	if numLeases > LEASESET2_MAX_LEASES {
		err := oops.
			Code("invalid_lease_count").
			With("num_leases", numLeases).
			With("max_allowed", LEASESET2_MAX_LEASES).
			Errorf("invalid lease count: %d (max %d)", numLeases, LEASESET2_MAX_LEASES)
		log.WithFields(logger.Fields{
			"pkg":         "lease_set2",
			"func":        "validateLeaseCount",
			"at":          "validateLeaseCount",
			"num_leases":  numLeases,
			"max_allowed": LEASESET2_MAX_LEASES,
		}).Error(err.Error())
		return err
	}
	return nil
}

// parseLease2Array parses an array of Lease2 objects from data.
// Returns the parsed leases, remaining data, and any error encountered.
func parseLease2Array(numLeases int, data []byte) ([]lease.Lease2, []byte, error) {
	leases := make([]lease.Lease2, numLeases)
	for i := 0; i < numLeases; i++ {
		lease2, rem, err := lease.ReadLease2(data)
		if err != nil {
			err = oops.
				Code("lease2_parse_failed").
				With("lease_index", i).
				Wrapf(err, "failed to parse Lease2 %d", i)
			log.WithFields(logger.Fields{
				"pkg":         "lease_set2",
				"func":        "parseLease2Array",
				"at":          "parseLease2Array",
				"lease_index": i,
			}).Error(err.Error())
			return nil, nil, err
		}
		leases[i] = lease2
		data = rem
		log.WithFields(logger.Fields{
			"pkg":         "lease_set2",
			"func":        "parseLease2Array",
			"lease_index": i,
		}).Debug("Parsed Lease2")
	}
	return leases, data, nil
}

func parseLeases(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	if err := validateLeaseCountData(len(data)); err != nil {
		return nil, err
	}

	numLeases := int(data[0])
	data = data[1:]

	// Spec: "All LeaseSet2 variants require at least one Lease."
	// Both the parser and Validate() enforce the minimum lease count.
	if err := validateLeaseCount(numLeases); err != nil {
		return nil, err
	}

	leases, remainder, err := parseLease2Array(numLeases, data)
	if err != nil {
		return nil, err
	}

	ls2.leases = leases
	return remainder, nil
}

// parseSignatureAndFinalize parses the signature and logs the successful completion.
// Returns remaining data after parsing or error if parsing fails.
func parseSignatureAndFinalize(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	defaultSigType := ls2.destination.KeyCertificate.SigningPublicKeyType()

	signature, rem, err := rootcommon.ParseLeaseSetSignature(
		data, defaultSigType, ls2.HasOfflineKeys(), ls2.offlineSignature, "LeaseSet2",
	)
	if err != nil {
		return nil, err
	}
	ls2.signature = signature

	log.WithFields(logger.Fields{
		"pkg":                 "lease_set2",
		"func":                "parseSignatureAndFinalize",
		"num_encryption_keys": len(ls2.encryptionKeys),
		"num_leases":          len(ls2.leases),
		"has_offline_keys":    ls2.HasOfflineKeys(),
		"is_unpublished":      ls2.IsUnpublished(),
		"is_blinded":          ls2.IsBlinded(),
	}).Debug("Successfully parsed LeaseSet2")

	return rem, nil
}

// NewLeaseSet2 creates a new LeaseSet2 from the provided components and signs it.
//
// This constructor creates a complete, signed LeaseSet2 structure ready for network publication.
// It validates all inputs, constructs the LeaseSet2 data structure, and generates the cryptographic
// signature using the provided signing key.
//
// Parameters:
//   - dest: Destination containing signing and encryption keys for this service
//   - published: Publication timestamp (seconds since Unix epoch)
//   - expiresOffset: Expiration offset in seconds from published time (max 65535)
//   - flags: LeaseSet2 flags (OFFLINE_KEYS, UNPUBLISHED, BLINDED)
//   - offlineSig: Optional offline signature (nil if not using offline keys)
//   - options: Service discovery options mapping (can be nil for no options)
//   - encryptionKeys: List of encryption keys (1-16 keys required)
//   - leases: List of Lease2 structures (0-16 leases allowed)
//   - signingKey: Private key for signing the LeaseSet2
//
// Returns:
//   - LeaseSet2: Constructed and signed LeaseSet2
//   - error: nil on success, validation or signing error otherwise
//
// Example:
//
//	ls2, err := NewLeaseSet2(
//	    destination,
//	    uint32(time.Now().Unix()),
//	    600,  // expires in 10 minutes
//	    0,    // no special flags
//	    nil,  // no offline signature
//	    nil,  // no options
//	    []EncryptionKey{{keyType: X25519, keyLen: 32, keyData: myKey}},
//	    []lease.Lease2{lease1, lease2},
//	    myPrivateKey,
//	)
func NewLeaseSet2(
	dest destination.Destination,
	published uint32,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	options common.Mapping,
	encryptionKeys []EncryptionKey,
	leases []lease.Lease2,
	signingKey interface{},
) (LeaseSet2, error) {
	log.WithFields(logger.Fields{"pkg": "lease_set2", "func": "NewLeaseSet2"}).Debug("Creating new LeaseSet2")

	if err := validateLeaseSet2AllInputs(dest, expiresOffset, flags, offlineSig, options, encryptionKeys, leases); err != nil {
		return LeaseSet2{}, err
	}

	dataToSign, err := serializeLeaseSet2ForSigning(dest, published, expiresOffset, flags, offlineSig, options, encryptionKeys, leases)
	if err != nil {
		return LeaseSet2{}, err
	}

	signature, err := signLeaseSet2Data(dest, offlineSig, signingKey, dataToSign)
	if err != nil {
		return LeaseSet2{}, err
	}

	ls2 := LeaseSet2{
		destination: dest, published: published, expires: expiresOffset,
		flags: flags, offlineSignature: offlineSig, options: options,
		encryptionKeys: encryptionKeys, leases: leases, signature: signature,
	}
	logLeaseSet2Creation(ls2)
	return ls2, nil
}

// validateLeaseSet2AllInputs validates all inputs including options sorting for LeaseSet2 creation.
func validateLeaseSet2AllInputs(
	dest destination.Destination,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	options common.Mapping,
	encryptionKeys []EncryptionKey,
	leases []lease.Lease2,
) error {
	if err := validateLeaseSet2Inputs(dest, expiresOffset, flags, offlineSig, encryptionKeys, leases); err != nil {
		return err
	}
	// "LS2 options MUST be sorted by key, so the signature is invariant."
	return validateOptionsSorted(options)
}

// signLeaseSet2Data determines the signature type and signs the serialized data.
func signLeaseSet2Data(dest destination.Destination, offlineSig *offline_signature.OfflineSignature, signingKey interface{}, dataToSign []byte) (signature sig.Signature, err error) {
	sigType := rootcommon.DetermineSignatureType(dest.KeyCertificate.SigningPublicKeyType(), offlineSig)
	signature, err = rootcommon.CreateLeaseSetSignature(signingKey, dataToSign, sigType, rootcommon.SignLeaseSetData)
	if err != nil {
		return signature, err
	}
	log.WithFields(logger.Fields{
		"pkg":            "lease_set2",
		"func":           "signLeaseSet2Data",
		"signature_type": sigType,
		"data_size":      len(dataToSign),
	}).Debug("Created LeaseSet2 signature")
	return signature, err
}

// logLeaseSet2Creation logs the successful creation of a LeaseSet2.
func logLeaseSet2Creation(ls2 LeaseSet2) {
	log.WithFields(logger.Fields{
		"pkg":                 "lease_set2",
		"func":                "logLeaseSet2Creation",
		"num_encryption_keys": len(ls2.encryptionKeys),
		"num_leases":          len(ls2.leases),
		"has_offline_keys":    ls2.HasOfflineKeys(),
		"published":           ls2.published,
		"expires_offset":      ls2.expires,
	}).Debug("Successfully created LeaseSet2")
}

// validateLeaseSet2Inputs validates all input parameters for LeaseSet2 creation.
func validateLeaseSet2Inputs(
	dest destination.Destination,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	encryptionKeys []EncryptionKey,
	leases []lease.Lease2,
) error {
	if err := validateDestinationSize(dest); err != nil {
		return err
	}
	if err := validateExpiresOffset(expiresOffset); err != nil {
		return err
	}
	if err := validateOfflineSignatureFlags(flags, offlineSig); err != nil {
		return err
	}
	if err := validateEncryptionKeyInputs(encryptionKeys); err != nil {
		return err
	}
	return validateLeaseInputs(leases)
}

// validateDestinationSize validates that the destination meets the minimum size requirement.
func validateDestinationSize(dest destination.Destination) error {
	destBytes, err := dest.Bytes()
	if err != nil {
		return oops.Errorf("invalid destination: %w", err)
	}
	if len(destBytes) < LEASESET2_MIN_DESTINATION_SIZE {
		return oops.
			Code("invalid_destination_size").
			With("size", len(destBytes)).
			With("minimum", LEASESET2_MIN_DESTINATION_SIZE).
			Errorf("destination size must be at least %d bytes", LEASESET2_MIN_DESTINATION_SIZE)
	}
	return nil
}

// validateExpiresOffset validates that the expiration offset is within allowed range.
// Note: The expires field is uint16, so it is naturally bounded to 0-65535 (the full
// range of LEASESET2_MAX_EXPIRES_OFFSET). No runtime check is needed, but we retain
// this function as a validation step placeholder and for documentation clarity.
func validateExpiresOffset(expiresOffset uint16) error {
	// uint16 is naturally bounded to 0-65535, which equals LEASESET2_MAX_EXPIRES_OFFSET.
	// No runtime check needed.
	return nil
}

// validateOfflineSignatureFlags validates consistency between the flags field and the
// presence of an offline signature. Also enforces the spec co-implication:
// BLINDED (bit 2) requires UNPUBLISHED (bit 1).
func validateOfflineSignatureFlags(flags uint16, offlineSig *offline_signature.OfflineSignature) error {
	if (flags&LEASESET2_FLAG_OFFLINE_KEYS) != 0 && offlineSig == nil {
		return oops.
			Code("missing_offline_signature").
			Errorf("OFFLINE_KEYS flag set but no offline signature provided")
	}
	if (flags&LEASESET2_FLAG_OFFLINE_KEYS) == 0 && offlineSig != nil {
		return oops.
			Code("unexpected_offline_signature").
			Errorf("offline signature provided but OFFLINE_KEYS flag not set")
	}
	// Spec: "If [BLINDED] is set, bit 1 (UNPUBLISHED) should also be set."
	if (flags&LEASESET2_FLAG_BLINDED) != 0 && (flags&LEASESET2_FLAG_UNPUBLISHED) == 0 {
		return oops.
			Code("blinded_requires_unpublished").
			Errorf("BLINDED flag (bit 2) requires UNPUBLISHED flag (bit 1) to also be set")
	}
	return nil
}

// validateEncryptionKeyInputs validates the encryption key count and internal consistency.
func validateEncryptionKeyInputs(encryptionKeys []EncryptionKey) error {
	if len(encryptionKeys) < 1 {
		return oops.
			Code("no_encryption_keys").
			Errorf("at least one encryption key is required")
	}
	if len(encryptionKeys) > LEASESET2_MAX_ENCRYPTION_KEYS {
		return oops.
			Code("too_many_encryption_keys").
			With("max_allowed", LEASESET2_MAX_ENCRYPTION_KEYS).
			Errorf("too many encryption keys: %d exceeds maximum %d", len(encryptionKeys), LEASESET2_MAX_ENCRYPTION_KEYS)
	}
	for i, key := range encryptionKeys {
		if int(key.KeyLen) != len(key.KeyData) {
			return oops.
				Code("encryption_key_len_mismatch").
				With("key_index", i).
				With("declared_len", key.KeyLen).
				With("actual_len", len(key.KeyData)).
				Errorf("encryption key %d: declared KeyLen %d does not match actual KeyData length %d", i, key.KeyLen, len(key.KeyData))
		}
	}
	return nil
}

// validateLeaseInputs validates the lease count is within the allowed range.
func validateLeaseInputs(leases []lease.Lease2) error {
	if len(leases) < 1 {
		return oops.
			Code("no_leases").
			Errorf("at least one lease is required per I2P specification")
	}
	if len(leases) > LEASESET2_MAX_LEASES {
		return oops.
			Code("too_many_leases").
			With("max_allowed", LEASESET2_MAX_LEASES).
			Errorf("too many leases: %d exceeds maximum %d", len(leases), LEASESET2_MAX_LEASES)
	}
	return nil
}

// serializeLeaseSet2ForSigning constructs the byte representation for signing.
// Per the I2P spec: "The signature is over the data above, PREPENDED with the
// single byte containing the DatabaseStore type (3)."
func serializeLeaseSet2ForSigning(
	dest destination.Destination,
	published uint32,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	options common.Mapping,
	encryptionKeys []EncryptionKey,
	leases []lease.Lease2,
) ([]byte, error) {
	content, err := serializeLeaseSet2Content(dest, published, expiresOffset, flags, offlineSig, options, encryptionKeys, leases)
	if err != nil {
		return nil, err
	}
	// Prepend DatabaseStore type byte (0x03) per I2P spec
	return rootcommon.PrependLeaseSetTypeByte(LEASESET2_DBSTORE_TYPE, content), nil
}

// serializeLeaseSet2Content serializes all LeaseSet2 fields (excluding the signature)
// into a byte slice. This shared helper is used by both Bytes() and serializeLeaseSet2ForSigning()
// to avoid duplicated serialization logic.
func serializeLeaseSet2Content(
	dest destination.Destination,
	published uint32,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	options common.Mapping,
	encryptionKeys []EncryptionKey,
	leases []lease.Lease2,
) ([]byte, error) {
	// Serialize the common header (dest, published, expires, flags, offlineSig, options)
	data, err := rootcommon.SerializeLeaseSetHeader(dest, published, expiresOffset, flags, offlineSig, options)
	if err != nil {
		return nil, err
	}

	// Add encryption keys
	data = append(data, byte(len(encryptionKeys)))
	for _, key := range encryptionKeys {
		data = rootcommon.AppendBigEndianUint16(data, key.KeyType)
		data = rootcommon.AppendBigEndianUint16(data, key.KeyLen)
		data = append(data, key.KeyData...)
	}

	// Add leases
	data = append(data, byte(len(leases)))
	for _, l := range leases {
		data = append(data, l.Bytes()...)
	}

	return data, nil
}

// NewLeaseSet2FromBytes is a convenience constructor that parses a LeaseSet2
// from raw bytes. It is equivalent to calling ReadLeaseSet2 but returns a
// pointer and discards the remainder, matching the NewXFromBytes pattern
// used by other packages in this codebase.
func NewLeaseSet2FromBytes(data []byte) (*LeaseSet2, []byte, error) {
	ls2, remainder, err := ReadLeaseSet2(data)
	if err != nil {
		return nil, remainder, err
	}
	return &ls2, remainder, nil
}
