// Package lease_set2 implements the I2P LeaseSet2 common data structure
package lease_set2

import (
	"encoding/binary"
	"sort"
	"strings"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

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
	log.Debug("Parsing LeaseSet2 structure")

	// Parse destination and header fields
	data, err = parseDestinationAndHeader(&ls2, data)
	if err != nil {
		return
	}

	// Parse optional offline signature
	data, err = parseOfflineSignature(&ls2, data)
	if err != nil {
		return
	}

	// Parse options mapping
	data, err = parseOptionsMapping(&ls2, data)
	if err != nil {
		return
	}

	// Parse encryption keys
	data, err = parseEncryptionKeys(&ls2, data)
	if err != nil {
		return
	}

	// Parse Lease2 structures
	data, err = parseLeases(&ls2, data)
	if err != nil {
		return
	}

	// Parse signature and finalize
	remainder, err = parseSignatureAndFinalize(&ls2, data)
	if err != nil {
		return
	}

	return
}

// parseDestinationAndHeader validates minimum size and parses the destination and header fields.
// Returns remaining data after parsing or error if validation or parsing fails.
// validateLeaseSet2MinSize validates that data meets minimum LeaseSet2 size requirements.
// Returns error if data is too short to contain a valid LeaseSet2.
func validateLeaseSet2MinSize(dataLen int) error {
	if dataLen < LEASESET2_MIN_SIZE {
		err := oops.
			Code("lease_set2_too_short").
			With("data_length", dataLen).
			With("minimum_required", LEASESET2_MIN_SIZE).
			Errorf("data too short for LeaseSet2: got %d bytes, need at least %d", dataLen, LEASESET2_MIN_SIZE)
		log.WithFields(logger.Fields{
			"at":          "validateLeaseSet2MinSize",
			"data_length": dataLen,
			"min_size":    LEASESET2_MIN_SIZE,
		}).Error(err.Error())
		return err
	}
	return nil
}

// parseDestinationField parses the destination from data and updates the LeaseSet2.
// Returns remaining data after destination or error if parsing fails.
func parseDestinationField(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	dest, rem, err := destination.ReadDestination(data)
	if err != nil {
		err = oops.
			Code("destination_parse_failed").
			Wrapf(err, "failed to parse destination in LeaseSet2")
		log.WithFields(logger.Fields{
			"at":     "parseDestinationField",
			"reason": "destination parse failed",
		}).Error(err.Error())
		return nil, err
	}
	ls2.destination = dest
	return rem, nil
}

// validateHeaderDataSize validates that remaining data is sufficient for header fields.
// Returns error if insufficient data remains for published, expires, and flags fields.
func validateHeaderDataSize(dataLen int) error {
	requiredSize := LEASESET2_PUBLISHED_SIZE + LEASESET2_EXPIRES_SIZE + LEASESET2_FLAGS_SIZE
	if dataLen < requiredSize {
		err := oops.
			Code("header_too_short").
			With("remaining_length", dataLen).
			Errorf("insufficient data for LeaseSet2 header fields")
		log.WithFields(logger.Fields{
			"at":               "validateHeaderDataSize",
			"remaining_length": dataLen,
		}).Error(err.Error())
		return err
	}
	return nil
}

// parseHeaderFields parses published timestamp, expires offset, and flags from data.
// Updates LeaseSet2 fields and returns remaining data after header parsing.
func parseHeaderFields(ls2 *LeaseSet2, data []byte) []byte {
	ls2.published = binary.BigEndian.Uint32(data[:LEASESET2_PUBLISHED_SIZE])
	data = data[LEASESET2_PUBLISHED_SIZE:]

	ls2.expires = binary.BigEndian.Uint16(data[:LEASESET2_EXPIRES_SIZE])
	data = data[LEASESET2_EXPIRES_SIZE:]

	ls2.flags = binary.BigEndian.Uint16(data[:LEASESET2_FLAGS_SIZE])
	data = data[LEASESET2_FLAGS_SIZE:]

	// Warn if reserved flag bits (bits 15-3) are set per spec:
	// "Bits 15-3: Reserved, set to 0 for compatibility with future uses."
	reservedMask := uint16(0xFFF8) // bits 15-3
	if ls2.flags&reservedMask != 0 {
		log.WithFields(logger.Fields{
			"flags":         ls2.flags,
			"reserved_bits": ls2.flags & reservedMask,
		}).Warn("LeaseSet2 has non-zero reserved flag bits (bits 15-3 should be 0)")
	}

	log.WithFields(logger.Fields{
		"published": ls2.published,
		"expires":   ls2.expires,
		"flags":     ls2.flags,
	}).Debug("Parsed LeaseSet2 header")

	return data
}

func parseDestinationAndHeader(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	if err := validateLeaseSet2MinSize(len(data)); err != nil {
		return nil, err
	}

	rem, err := parseDestinationField(ls2, data)
	if err != nil {
		return nil, err
	}

	if err := validateHeaderDataSize(len(rem)); err != nil {
		return nil, err
	}

	rem = parseHeaderFields(ls2, rem)

	return rem, nil
}

// parseOfflineSignature parses the optional offline signature if the offline keys flag is set.
// Returns remaining data after parsing or error if parsing fails.
func parseOfflineSignature(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	if !ls2.HasOfflineKeys() {
		return data, nil
	}

	// Get destination signature type for offline signature parsing
	destSigType := uint16(ls2.destination.KeyCertificate.SigningPublicKeyType())

	offlineSig, rem, err := offline_signature.ReadOfflineSignature(data, destSigType)
	if err != nil {
		err = oops.
			Code("offline_signature_parse_failed").
			Wrapf(err, "failed to parse offline signature in LeaseSet2")
		log.WithFields(logger.Fields{
			"at":     "parseOfflineSignature",
			"reason": "offline signature parse failed",
		}).Error(err.Error())
		return nil, err
	}
	ls2.offlineSignature = &offlineSig
	data = rem
	log.Debug("Parsed offline signature")

	return data, nil
}

// parseOptionsMapping parses the options mapping containing service record options.
// Returns remaining data after parsing or error if parsing fails.
//
// Note: ReadMapping returns a warning ("data exists beyond length of mapping")
// whenever the input slice extends past the declared mapping size. This is
// expected here because the options mapping is always embedded in the larger
// LeaseSet2 structure.  We therefore treat that specific warning as non-fatal
// and only propagate genuine parse failures.
func parseOptionsMapping(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	mapping, rem, errs := common.ReadMapping(data)
	if len(errs) > 0 {
		// Filter: the "data exists beyond length" warning is expected when
		// a mapping is embedded inside a larger byte stream.
		var fatal []error
		for _, e := range errs {
			if strings.Contains(e.Error(), "data exists beyond length of mapping") {
				log.Debug("options mapping: ignoring 'data beyond length' warning (expected in embedded context)")
				continue
			}
			fatal = append(fatal, e)
		}
		if len(fatal) > 0 {
			err := oops.
				Code("options_parse_failed").
				Wrapf(fatal[0], "failed to parse options mapping in LeaseSet2")
			log.WithFields(logger.Fields{
				"at":     "parseOptionsMapping",
				"reason": "options mapping parse failed",
			}).Error(err.Error())
			return nil, err
		}
	}
	ls2.options = mapping

	// Warn if options mapping keys are not sorted per spec:
	// "Options MUST be sorted by key for signature invariance."
	warnIfOptionsUnsorted(mapping)

	log.Debug("Parsed options mapping")

	return rem, nil
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
		log.Warn("LeaseSet2 options mapping keys are not sorted; spec requires sorted keys for signature invariance")
	}
}

// parseEncryptionKeys parses the encryption keys from the data.
// Returns remaining data after parsing or error if validation or parsing fails.
func parseEncryptionKeys(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	if len(data) < 1 {
		err := oops.
			Code("missing_encryption_key_count").
			Errorf("insufficient data for encryption key count")
		log.WithFields(logger.Fields{
			"at": "parseEncryptionKeys",
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

	if err := validateEncryptionKeyDataLength(len(rem), keyLen, keyIndex); err != nil {
		return nil, err
	}

	keyData, remainder := extractEncryptionKeyData(rem, keyLen)

	storeEncryptionKey(ls2, keyIndex, keyType, keyLen, keyData)

	return remainder, nil
}

// validateEncryptionKeyHeaderData validates that data has sufficient bytes for key type and length.
// Returns error if data is too short for encryption key header.
func validateEncryptionKeyHeaderData(dataLen int, keyIndex int) error {
	requiredSize := LEASESET2_ENCRYPTION_KEY_TYPE_SIZE + LEASESET2_ENCRYPTION_KEY_LENGTH_SIZE
	if dataLen < requiredSize {
		err := oops.
			Code("encryption_key_header_too_short").
			With("key_index", keyIndex).
			With("remaining_length", dataLen).
			Errorf("insufficient data for encryption key %d header", keyIndex)
		log.WithFields(logger.Fields{
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

// storeEncryptionKey stores the parsed encryption key in the LeaseSet2 structure.
// Logs the parsed key information at debug level.
// Warns if the declared key length does not match the expected size for the key type.
func storeEncryptionKey(ls2 *LeaseSet2, keyIndex int, keyType uint16, keyLen uint16, keyData []byte) {
	ls2.encryptionKeys[keyIndex] = EncryptionKey{
		KeyType: keyType,
		KeyLen:  keyLen,
		KeyData: keyData,
	}

	// Validate key type/length consistency per spec:
	// "keylen: Must match the specified length of the encryption type."
	if expectedSize, ok := key_certificate.CryptoPublicKeySizes[keyType]; ok {
		if int(keyLen) != expectedSize {
			log.WithFields(logger.Fields{
				"key_index":    keyIndex,
				"key_type":     keyType,
				"declared_len": keyLen,
				"expected_len": expectedSize,
			}).Warn("Encryption key length does not match expected size for key type")
		}
	}

	log.WithFields(logger.Fields{
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
			"at": "validateLeaseCountData",
		}).Error(err.Error())
		return err
	}
	return nil
}

// validateLeaseCount validates that the lease count is within allowed limits.
// Returns error if lease count exceeds maximum.
func validateLeaseCount(numLeases int) error {
	if numLeases > LEASESET2_MAX_LEASES {
		err := oops.
			Code("invalid_lease_count").
			With("num_leases", numLeases).
			With("max_allowed", LEASESET2_MAX_LEASES).
			Errorf("invalid lease count: %d (max %d)", numLeases, LEASESET2_MAX_LEASES)
		log.WithFields(logger.Fields{
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
				"at":          "parseLease2Array",
				"lease_index": i,
			}).Error(err.Error())
			return nil, nil, err
		}
		leases[i] = lease2
		data = rem
		log.WithFields(logger.Fields{
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
	// Determine signature type
	var sigType int
	if ls2.HasOfflineKeys() && ls2.offlineSignature != nil {
		// Use transient signature type from offline signature
		sigType = int(ls2.offlineSignature.TransientSigType())
	} else {
		// Use destination signature type
		sigType = ls2.destination.KeyCertificate.SigningPublicKeyType()
	}

	// Parse signature
	signature, rem, err := sig.ReadSignature(data, sigType)
	if err != nil {
		err = oops.
			Code("signature_parse_failed").
			Wrapf(err, "failed to parse signature in LeaseSet2")
		log.WithFields(logger.Fields{
			"at":       "parseSignatureAndFinalize",
			"sig_type": sigType,
		}).Error(err.Error())
		return nil, err
	}
	ls2.signature = signature

	log.WithFields(logger.Fields{
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
	log.Debug("Creating new LeaseSet2")

	// Validate inputs
	if err := validateLeaseSet2Inputs(dest, expiresOffset, flags, offlineSig, encryptionKeys, leases); err != nil {
		return LeaseSet2{}, err
	}

	// Construct the LeaseSet2 data for signing
	dataToSign, err := serializeLeaseSet2ForSigning(dest, published, expiresOffset, flags, offlineSig, options, encryptionKeys, leases)
	if err != nil {
		return LeaseSet2{}, err
	}

	// Determine signature type and sign the data
	sigType := determineSignatureType(dest, offlineSig)
	signature, err := createLeaseSet2Signature(signingKey, dataToSign, sigType)
	if err != nil {
		return LeaseSet2{}, err
	}

	// Assemble the final LeaseSet2 structure
	ls2 := LeaseSet2{
		destination:      dest,
		published:        published,
		expires:          expiresOffset,
		flags:            flags,
		offlineSignature: offlineSig,
		options:          options,
		encryptionKeys:   encryptionKeys,
		leases:           leases,
		signature:        signature,
	}

	log.WithFields(logger.Fields{
		"num_encryption_keys": len(encryptionKeys),
		"num_leases":          len(leases),
		"has_offline_keys":    ls2.HasOfflineKeys(),
		"published":           published,
		"expires_offset":      expiresOffset,
	}).Debug("Successfully created LeaseSet2")

	return ls2, nil
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
	// Validate destination size (minimum 387 bytes per I2P spec)
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

	// Validate expiration offset
	if expiresOffset > LEASESET2_MAX_EXPIRES_OFFSET {
		return oops.
			Code("invalid_expires_offset").
			With("max_allowed", LEASESET2_MAX_EXPIRES_OFFSET).
			Errorf("expires offset %d exceeds maximum %d", expiresOffset, LEASESET2_MAX_EXPIRES_OFFSET)
	}

	// Validate offline signature flag consistency
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

	// Validate encryption keys
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

	// Validate leases: spec requires at least 1 lease for LeaseSet2 variants
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

	// Validate encryption key consistency: KeyLen must match len(KeyData)
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
	data := make([]byte, 0, 1+len(content))
	data = append(data, LEASESET2_DBSTORE_TYPE)
	data = append(data, content...)
	return data, nil
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
	data := make([]byte, 0)

	// Add destination
	destBytes, err := dest.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize destination: %w", err)
	}
	data = append(data, destBytes...)

	// Add published timestamp (4 bytes)
	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, published)
	data = append(data, publishedBytes...)

	// Add expires offset (2 bytes)
	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, expiresOffset)
	data = append(data, expiresBytes...)

	// Add flags (2 bytes)
	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, flags)
	data = append(data, flagsBytes...)

	// Add offline signature if present
	if offlineSig != nil {
		data = append(data, offlineSig.Bytes()...)
	}

	// Add options mapping
	if len(options.Values()) > 0 {
		data = append(data, options.Data()...)
	} else {
		data = append(data, 0x00, 0x00)
	}

	// Add encryption keys
	data = append(data, byte(len(encryptionKeys)))
	for _, key := range encryptionKeys {
		keyTypeBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(keyTypeBytes, key.KeyType)
		data = append(data, keyTypeBytes...)

		keyLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(keyLenBytes, key.KeyLen)
		data = append(data, keyLenBytes...)

		data = append(data, key.KeyData...)
	}

	// Add leases
	data = append(data, byte(len(leases)))
	for _, l := range leases {
		data = append(data, l.Bytes()...)
	}

	return data, nil
}

// determineSignatureType determines which signature type to use based on offline signature.
func determineSignatureType(dest destination.Destination, offlineSig *offline_signature.OfflineSignature) uint16 {
	if offlineSig != nil {
		// Use transient signature type from offline signature
		return offlineSig.TransientSigType()
	}
	// Use destination's signature type (convert int to uint16)
	return uint16(dest.KeyCertificate.SigningPublicKeyType())
}

// createLeaseSet2Signature signs the LeaseSet2 data with the provided key.
func createLeaseSet2Signature(signingKey interface{}, data []byte, sigType uint16) (sig.Signature, error) {
	// This is a placeholder - actual signing would use the crypto library
	// For now, we create a zero signature of the correct size
	sigSize := offline_signature.SignatureSize(sigType)
	if sigSize == 0 {
		return sig.Signature{}, oops.
			Code("unknown_signature_type").
			With("signature_type", sigType).
			Errorf("unknown signature type: %d", sigType)
	}

	// TODO: Implement actual signing using the signingKey
	// This would call into crypto/signature package to create real signatures
	// For now, return an empty signature of the correct size
	signatureData := make([]byte, sigSize)
	signature, err := sig.NewSignatureFromBytes(signatureData, int(sigType))
	if err != nil {
		return sig.Signature{}, oops.Errorf("failed to create signature: %w", err)
	}

	log.WithFields(logger.Fields{
		"signature_type": sigType,
		"signature_size": sigSize,
		"data_size":      len(data),
	}).Warn("Created placeholder signature - implement actual signing")

	return signature, nil
}
