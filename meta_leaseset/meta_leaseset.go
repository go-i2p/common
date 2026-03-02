// Package meta_leaseset implements the I2P MetaLeaseSet common data structure
package meta_leaseset

import (
	"encoding/binary"
	"sort"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// ReadMetaLeaseSet parses a MetaLeaseSet structure from the provided byte slice.
// Returns the parsed MetaLeaseSet, remaining bytes, and any error encountered.
//
// The parsing process follows I2P specification 0.9.67:
//  1. Parse destination (387+ bytes)
//  2. Parse published timestamp (4 bytes)
//  3. Parse expires offset (2 bytes)
//  4. Parse flags (2 bytes)
//  5. If flags bit 0 set, parse offline signature (variable length)
//  6. Parse options mapping (2+ bytes)
//  7. Parse number of entries (1 byte, 1-16)
//  8. Parse entries (40+ bytes each)
//  9. Parse number of revocations (1 byte) and revocation hashes (32 bytes each)
//
// 10. Parse signature (variable length based on signature type)
//
// Returns error if:
//   - Data is too short for minimum MetaLeaseSet size
//   - Destination parsing fails
//   - Any component parsing fails
//   - Number of entries is out of valid range (1-16)
//
// https://geti2p.net/spec/common-structures#metaleaseset
func ReadMetaLeaseSet(data []byte) (mls MetaLeaseSet, remainder []byte, err error) {
	log.Debug("Parsing MetaLeaseSet structure")

	// Parse destination and header fields
	data, err = parseDestinationAndHeader(&mls, data)
	if err != nil {
		return
	}

	// Parse optional offline signature
	data, err = parseOfflineSignature(&mls, data)
	if err != nil {
		return
	}

	// Parse options mapping
	data, err = parseOptionsMapping(&mls, data)
	if err != nil {
		return
	}

	// Parse entries
	data, err = parseEntries(&mls, data)
	if err != nil {
		return
	}

	// Parse revocations (numr + revocation hashes)
	data, err = parseRevocations(&mls, data)
	if err != nil {
		return
	}

	// Parse signature and finalize
	remainder, err = parseSignatureAndFinalize(&mls, data)
	if err != nil {
		return
	}

	return
}

// parseDestinationAndHeader validates minimum size and parses the destination and header fields.
// Returns remaining data after parsing or error if validation or parsing fails.
func parseDestinationAndHeader(mls *MetaLeaseSet, data []byte) ([]byte, error) {
	if err := validateMinSize(len(data)); err != nil {
		return nil, err
	}

	rem, err := parseDestinationField(mls, data)
	if err != nil {
		return nil, err
	}

	if err := validateHeaderDataSize(len(rem)); err != nil {
		return nil, err
	}

	rem = parseHeaderFields(mls, rem)

	return rem, nil
}

// validateMinSize validates that data meets minimum MetaLeaseSet size requirements.
// Returns error if data is too short to contain a valid MetaLeaseSet.
func validateMinSize(dataLen int) error {
	if dataLen < META_LEASESET_MIN_SIZE {
		err := oops.
			Code("meta_leaseset_too_short").
			With("data_length", dataLen).
			With("minimum_required", META_LEASESET_MIN_SIZE).
			Errorf("data too short for MetaLeaseSet: got %d bytes, need at least %d", dataLen, META_LEASESET_MIN_SIZE)
		log.WithFields(logger.Fields{
			"at":          "validateMinSize",
			"data_length": dataLen,
			"min_size":    META_LEASESET_MIN_SIZE,
		}).Error(err.Error())
		return err
	}
	return nil
}

// parseDestinationField parses the destination from data and updates the MetaLeaseSet.
// Returns remaining data after destination or error if parsing fails.
func parseDestinationField(mls *MetaLeaseSet, data []byte) ([]byte, error) {
	dest, rem, err := destination.ReadDestination(data)
	if err != nil {
		err = oops.
			Code("destination_parse_failed").
			Wrapf(err, "failed to parse destination in MetaLeaseSet")
		log.WithFields(logger.Fields{
			"at":     "parseDestinationField",
			"reason": "destination parse failed",
		}).Error(err.Error())
		return nil, err
	}
	mls.destination = dest
	return rem, nil
}

// validateHeaderDataSize validates that remaining data is sufficient for header fields.
// Returns error if insufficient data remains for published, expires, and flags fields.
func validateHeaderDataSize(dataLen int) error {
	requiredSize := META_LEASESET_PUBLISHED_SIZE + META_LEASESET_EXPIRES_SIZE + META_LEASESET_FLAGS_SIZE
	if dataLen < requiredSize {
		err := oops.
			Code("header_too_short").
			With("remaining_length", dataLen).
			With("required_size", requiredSize).
			Errorf("insufficient data for MetaLeaseSet header fields")
		log.WithFields(logger.Fields{
			"at":               "validateHeaderDataSize",
			"remaining_length": dataLen,
			"required_size":    requiredSize,
		}).Error(err.Error())
		return err
	}
	return nil
}

// parseHeaderFields parses published timestamp, expires offset, and flags from data.
// Updates MetaLeaseSet fields and returns remaining data after header parsing.
func parseHeaderFields(mls *MetaLeaseSet, data []byte) []byte {
	mls.published = binary.BigEndian.Uint32(data[:META_LEASESET_PUBLISHED_SIZE])
	data = data[META_LEASESET_PUBLISHED_SIZE:]

	mls.expires = binary.BigEndian.Uint16(data[:META_LEASESET_EXPIRES_SIZE])
	data = data[META_LEASESET_EXPIRES_SIZE:]

	mls.flags = binary.BigEndian.Uint16(data[:META_LEASESET_FLAGS_SIZE])
	data = data[META_LEASESET_FLAGS_SIZE:]

	log.WithFields(logger.Fields{
		"published": mls.published,
		"expires":   mls.expires,
		"flags":     mls.flags,
	}).Debug("Parsed MetaLeaseSet header")

	return data
}

// parseOfflineSignature parses the optional offline signature if the offline keys flag is set.
// Returns remaining data after parsing or error if parsing fails.
func parseOfflineSignature(mls *MetaLeaseSet, data []byte) ([]byte, error) {
	if !mls.HasOfflineKeys() {
		return data, nil
	}

	// Get destination signature type for offline signature parsing
	destSigType := uint16(mls.destination.KeyCertificate.SigningPublicKeyType())

	offlineSig, rem, err := offline_signature.ReadOfflineSignature(data, destSigType)
	if err != nil {
		err = oops.
			Code("offline_signature_parse_failed").
			Wrapf(err, "failed to parse offline signature in MetaLeaseSet")
		log.WithFields(logger.Fields{
			"at":     "parseOfflineSignature",
			"reason": "offline signature parse failed",
		}).Error(err.Error())
		return nil, err
	}
	mls.offlineSignature = &offlineSig
	data = rem
	log.Debug("Parsed offline signature")

	return data, nil
}

// parseOptionsMapping parses the options mapping containing service record options.
// Returns remaining data after parsing or error if parsing fails.
func parseOptionsMapping(mls *MetaLeaseSet, data []byte) ([]byte, error) {
	mapping, rem, errs := common.ReadMapping(data)
	if len(errs) > 0 {
		err := oops.
			Code("options_parse_failed").
			Wrapf(errs[0], "failed to parse options mapping in MetaLeaseSet")
		log.WithFields(logger.Fields{
			"at":     "parseOptionsMapping",
			"reason": "options mapping parse failed",
		}).Error(err.Error())
		return nil, err
	}
	mls.options = mapping
	log.Debug("Parsed options mapping")

	return rem, nil
}

// parseEntries parses the MetaLeaseSet entries from the data.
// Returns remaining data after parsing or error if validation or parsing fails.
func parseEntries(mls *MetaLeaseSet, data []byte) ([]byte, error) {
	if len(data) < META_LEASESET_NUM_ENTRIES_SIZE {
		err := oops.
			Code("missing_entry_count").
			Errorf("insufficient data for entry count")
		log.WithFields(logger.Fields{
			"at": "parseEntries",
		}).Error(err.Error())
		return nil, err
	}

	numEntries := uint8(data[0])
	data = data[META_LEASESET_NUM_ENTRIES_SIZE:]

	if err := validateEntryCount(int(numEntries)); err != nil {
		return nil, err
	}

	mls.numEntries = numEntries
	mls.entries = make([]MetaLeaseSetEntry, numEntries)

	for i := 0; i < int(numEntries); i++ {
		var err error
		data, err = parseSingleEntry(mls, i, data)
		if err != nil {
			return nil, err
		}
	}

	log.WithFields(logger.Fields{
		"num_entries": numEntries,
	}).Debug("Parsed all MetaLeaseSet entries")

	return data, nil
}

// validateEntryCount validates that the entry count is within allowed limits (1-16).
// Returns error if entry count is out of range.
func validateEntryCount(numEntries int) error {
	if numEntries < META_LEASESET_MIN_ENTRIES || numEntries > META_LEASESET_MAX_ENTRIES {
		err := oops.
			Code("invalid_entry_count").
			With("num_entries", numEntries).
			With("min_allowed", META_LEASESET_MIN_ENTRIES).
			With("max_allowed", META_LEASESET_MAX_ENTRIES).
			Errorf("invalid entry count: %d (must be %d-%d)", numEntries, META_LEASESET_MIN_ENTRIES, META_LEASESET_MAX_ENTRIES)
		log.WithFields(logger.Fields{
			"at":          "validateEntryCount",
			"num_entries": numEntries,
		}).Error(err.Error())
		return err
	}
	return nil
}

// parseSingleEntry parses a single MetaLeaseSetEntry at the specified index.
// Returns remaining data after parsing or error if parsing fails.
func parseSingleEntry(mls *MetaLeaseSet, entryIndex int, data []byte) ([]byte, error) {
	if err := validateEntryMinSize(entryIndex, len(data)); err != nil {
		return nil, err
	}

	var entry MetaLeaseSetEntry
	data = parseEntryFixedFields(&entry, data)

	if err := validateEntryType(entry.Type(), entryIndex); err != nil {
		return nil, err
	}

	mls.entries[entryIndex] = entry
	logParsedEntry(entryIndex, &entry)
	return data, nil
}

// validateEntryMinSize checks that there is enough data remaining to read the
// fixed-size header fields of a MetaLeaseSet entry.
func validateEntryMinSize(entryIndex int, dataLen int) error {
	if dataLen < META_LEASESET_ENTRY_SIZE {
		err := oops.
			Code("entry_too_short").
			With("entry_index", entryIndex).
			With("remaining_length", dataLen).
			With("minimum_required", META_LEASESET_ENTRY_SIZE).
			Errorf("insufficient data for entry %d", entryIndex)
		log.WithFields(logger.Fields{
			"at":          "parseSingleEntry",
			"entry_index": entryIndex,
		}).Error(err.Error())
		return err
	}
	return nil
}

// parseEntryFixedFields reads the hash, flags, cost, and end_date fields from data
// into the entry and returns the remaining data.
// Per spec: hash(32) + flags(3) + cost(1) + end_date(4) = 40 bytes.
func parseEntryFixedFields(entry *MetaLeaseSetEntry, data []byte) []byte {
	copy(entry.hash[:], data[:META_LEASESET_ENTRY_HASH_SIZE])
	data = data[META_LEASESET_ENTRY_HASH_SIZE:]

	copy(entry.flags[:], data[:META_LEASESET_ENTRY_FLAGS_SIZE])
	data = data[META_LEASESET_ENTRY_FLAGS_SIZE:]

	entry.cost = data[0]
	data = data[META_LEASESET_ENTRY_COST_SIZE:]

	entry.endDate = binary.BigEndian.Uint32(data[:META_LEASESET_ENTRY_END_DATE_SIZE])
	data = data[META_LEASESET_ENTRY_END_DATE_SIZE:]

	return data
}

// logParsedEntry logs diagnostic details after successfully parsing a MetaLeaseSet entry.
func logParsedEntry(entryIndex int, entry *MetaLeaseSetEntry) {
	log.WithFields(logger.Fields{
		"entry_index": entryIndex,
		"type":        entry.Type(),
		"cost":        entry.cost,
		"end_date":    entry.endDate,
	}).Debug("Parsed MetaLeaseSet entry")
}

// validateEntryType validates the entry type (from flags bits 3-0).
// Per the I2P spec, defined types are: 0 (unknown), 1 (LeaseSet), 3 (LeaseSet2),
// 5 (MetaLeaseSet). Values 2, 4, and 6–15 are currently reserved. To maintain
// forward compatibility with future spec revisions, unrecognised values are
// accepted with a warning rather than causing a hard parse failure.
func validateEntryType(leaseType uint8, entryIndex int) error {
	switch leaseType {
	case META_LEASESET_ENTRY_TYPE_UNKNOWN,
		META_LEASESET_ENTRY_TYPE_LEASESET,
		META_LEASESET_ENTRY_TYPE_LEASESET2,
		META_LEASESET_ENTRY_TYPE_META_LEASESET:
		return nil
	default:
		// Treat unrecognised entry types as forward-compatible unknowns.
		// Returning an error here would break parsing of MetaLeaseSets
		// produced by implementations that use future reserved type values.
		log.WithFields(logger.Fields{
			"at":          "validateEntryType",
			"entry_index": entryIndex,
			"lease_type":  leaseType,
		}).Warn("unrecognised MetaLease entry type; treating as unknown (forward-compatible)")
		return nil
	}
}

// parseSignatureAndFinalize parses the signature and logs the successful completion.
// Returns remaining data after parsing or error if parsing fails.
func parseSignatureAndFinalize(mls *MetaLeaseSet, data []byte) ([]byte, error) {
	// Determine signature type
	var sigType int
	if mls.HasOfflineKeys() && mls.offlineSignature != nil {
		// Use transient signature type from offline signature
		sigType = int(mls.offlineSignature.TransientSigType())
	} else {
		// Use destination signature type
		sigType = mls.destination.KeyCertificate.SigningPublicKeyType()
	}

	// Parse signature
	signature, rem, err := sig.ReadSignature(data, sigType)
	if err != nil {
		err = oops.
			Code("signature_parse_failed").
			Wrapf(err, "failed to parse signature in MetaLeaseSet")
		log.WithFields(logger.Fields{
			"at":       "parseSignatureAndFinalize",
			"sig_type": sigType,
		}).Error(err.Error())
		return nil, err
	}
	mls.signature = signature

	log.WithFields(logger.Fields{
		"num_entries":      mls.numEntries,
		"has_offline_keys": mls.HasOfflineKeys(),
		"is_unpublished":   mls.IsUnpublished(),
	}).Debug("Successfully parsed MetaLeaseSet")

	return rem, nil
}

// Accessor methods for MetaLeaseSet

// Destination returns the destination identity associated with this MetaLeaseSet.
func (mls *MetaLeaseSet) Destination() destination.Destination {
	return mls.destination
}

// Published returns the published timestamp as a uint32 (seconds since Unix epoch).
func (mls *MetaLeaseSet) Published() uint32 {
	return mls.published
}

// PublishedTime returns the published timestamp as a Go time.Time value.
func (mls *MetaLeaseSet) PublishedTime() time.Time {
	return time.Unix(int64(mls.published), 0).UTC()
}

// Expires returns the expiration offset in seconds from the published timestamp.
func (mls *MetaLeaseSet) Expires() uint16 {
	return mls.expires
}

// ExpirationTime returns the absolute expiration time as a Go time.Time value.
func (mls *MetaLeaseSet) ExpirationTime() time.Time {
	return mls.PublishedTime().Add(time.Duration(mls.expires) * time.Second)
}

// IsExpired checks if the MetaLeaseSet has expired based on the current time.
func (mls *MetaLeaseSet) IsExpired() bool {
	return time.Now().After(mls.ExpirationTime())
}

// Flags returns the raw flags value (2 bytes).
func (mls *MetaLeaseSet) Flags() uint16 {
	return mls.flags
}

// HasOfflineKeys returns true if the offline signature flag is set (bit 0).
func (mls *MetaLeaseSet) HasOfflineKeys() bool {
	return (mls.flags & META_LEASESET_FLAG_OFFLINE_KEYS) != 0
}

// IsUnpublished returns true if the unpublished flag is set (bit 1).
func (mls *MetaLeaseSet) IsUnpublished() bool {
	return (mls.flags & META_LEASESET_FLAG_UNPUBLISHED) != 0
}

// IsBlinded returns true if the blinded flag is set (bit 2).
// A blinded MetaLeaseSet MUST NOT be flooded or returned in response to normal
// netdb queries; consumers must route through the blinding protocol.
func (mls *MetaLeaseSet) IsBlinded() bool {
	return (mls.flags & META_LEASESET_FLAG_BLINDED) != 0
}

// OfflineSignature returns the optional offline signature structure.
func (mls *MetaLeaseSet) OfflineSignature() *offline_signature.OfflineSignature {
	return mls.offlineSignature
}

// Options returns the mapping containing service record options.
func (mls *MetaLeaseSet) Options() common.Mapping {
	return mls.options
}

// Signature returns the signature over the MetaLeaseSet data.
func (mls *MetaLeaseSet) Signature() sig.Signature {
	return mls.signature
}

// NumEntries returns the number of entries in this MetaLeaseSet.
func (mls *MetaLeaseSet) NumEntries() int {
	return int(mls.numEntries)
}

// Entries returns the slice of MetaLeaseSetEntry structures.
func (mls *MetaLeaseSet) Entries() []MetaLeaseSetEntry {
	return mls.entries
}

// GetEntry returns the entry at the specified index.
// Returns error if index is out of range.
func (mls *MetaLeaseSet) GetEntry(index int) (MetaLeaseSetEntry, error) {
	if index < 0 || index >= len(mls.entries) {
		return MetaLeaseSetEntry{}, oops.
			Code("entry_index_out_of_range").
			With("index", index).
			With("num_entries", len(mls.entries)).
			Errorf("entry index %d out of range [0, %d)", index, len(mls.entries))
	}
	return mls.entries[index], nil
}

// FindEntriesByType returns all entries matching the specified lease set type.
// Valid types: 0 (unknown), 1 (LeaseSet), 3 (LeaseSet2), 5 (MetaLeaseSet)
func (mls *MetaLeaseSet) FindEntriesByType(leaseType uint8) []MetaLeaseSetEntry {
	var matched []MetaLeaseSetEntry
	for _, entry := range mls.entries {
		if entry.Type() == leaseType {
			matched = append(matched, entry)
		}
	}
	return matched
}

// SortEntriesByCost returns a copy of entries sorted by cost (lowest first).
// Lower cost values indicate preferred entries for load balancing.
func (mls *MetaLeaseSet) SortEntriesByCost() []MetaLeaseSetEntry {
	sorted := make([]MetaLeaseSetEntry, len(mls.entries))
	copy(sorted, mls.entries)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].cost < sorted[j].cost
	})

	return sorted
}

// Entry accessor methods

// Hash returns the SHA256 hash of the referenced lease set.
func (entry *MetaLeaseSetEntry) Hash() [32]byte {
	return entry.hash
}

// Flags returns the 3-byte flags field of the entry.
// Bits 3-0 encode the entry type, bits 23-4 are reserved.
func (entry *MetaLeaseSetEntry) Flags() [3]byte {
	return entry.flags
}

// Type returns the type of the referenced lease set, extracted from flags bits 3-0.
// Valid types: 0 (unknown), 1 (LeaseSet), 3 (LeaseSet2), 5 (MetaLeaseSet)
func (entry *MetaLeaseSetEntry) Type() uint8 {
	return entry.flags[2] & 0x0F
}

// Expires returns the expiration timestamp (seconds since Unix epoch).
func (entry *MetaLeaseSetEntry) Expires() uint32 {
	return entry.endDate
}

// ExpiresTime returns the expiration time as a Go time.Time value.
func (entry *MetaLeaseSetEntry) ExpiresTime() time.Time {
	return time.Unix(int64(entry.endDate), 0).UTC()
}

// IsExpired checks if the entry has expired based on the current time.
func (entry *MetaLeaseSetEntry) IsExpired() bool {
	return time.Now().After(entry.ExpiresTime())
}

// Cost returns the cost metric for load balancing (lower is better).
func (entry *MetaLeaseSetEntry) Cost() uint8 {
	return entry.cost
}

// Bytes serializes the MetaLeaseSet to its wire format representation.
// Returns the complete byte representation that can be stored in the network database.
//
// Wire format order:
//  1. Destination (387+ bytes)
//  2. Published timestamp (4 bytes)
//  3. Expires offset (2 bytes)
//  4. Flags (2 bytes)
//  5. [Offline signature] (variable, if flags bit 0 set)
//  6. Options mapping (2+ bytes)
//  7. Number of entries (1 byte)
//  8. Entries (40+ bytes each)
//  9. Signature (variable, based on signature type)
//
// The signature must be generated over all preceding data prepended with
// the DatabaseStore type byte (0x07 for MetaLeaseSet).
func (mls *MetaLeaseSet) Bytes() ([]byte, error) {
	result := make([]byte, 0)

	// Add destination
	// Use Destination.Bytes() to guard against a nil KeysAndCert pointer.
	destBytes, err := mls.destination.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize destination: %w", err)
	}
	result = append(result, destBytes...)

	// Add published timestamp (4 bytes)
	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, mls.published)
	result = append(result, publishedBytes...)

	// Add expires offset (2 bytes)
	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, mls.expires)
	result = append(result, expiresBytes...)

	// Add flags (2 bytes)
	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, mls.flags)
	result = append(result, flagsBytes...)

	// Add offline signature if present
	if mls.offlineSignature != nil {
		result = append(result, mls.offlineSignature.Bytes()...)
	}

	// Add options mapping, sorted by key for signature invariance.
	// ValuesToMapping applies the canonical Java String.compareTo() key order
	// required by the I2P spec so that signature verification succeeds on all
	// conforming receivers.
	if len(mls.options.Values()) > 0 {
		sortedOpts, sortErr := common.ValuesToMapping(mls.options.Values())
		if sortErr != nil {
			return nil, oops.Errorf("failed to sort options mapping: %w", sortErr)
		}
		result = append(result, sortedOpts.Data()...)
	} else {
		// Empty mapping (2 bytes of zero)
		result = append(result, 0x00, 0x00)
	}

	// Add number of entries
	result = append(result, mls.numEntries)

	// Add each entry
	for i, entry := range mls.entries {
		entryBytes, err := entry.Bytes()
		if err != nil {
			return nil, oops.Wrapf(err, "failed to serialize entry %d", i)
		}
		result = append(result, entryBytes...)
	}

	// Add number of revocations (1 byte)
	result = append(result, mls.numRevocations)

	// Add revocation hashes (32 bytes each)
	for _, hash := range mls.revocations {
		result = append(result, hash[:]...)
	}

	// Add signature
	result = append(result, mls.signature.Bytes()...)

	log.WithFields(logger.Fields{
		"total_size":       len(result),
		"destination_size": len(destBytes),
		"num_entries":      mls.numEntries,
		"has_offline_sig":  mls.offlineSignature != nil,
		"options_count":    len(mls.options.Values()),
	}).Debug("Serialized MetaLeaseSet to bytes")

	return result, nil
}

// Bytes serializes a MetaLeaseSetEntry to its wire format representation.
// Returns the byte representation of this entry (exactly 40 bytes).
//
// Per the I2P MetaLease spec, wire format is:
//  1. Hash (32 bytes)
//  2. Flags (3 bytes) — bits 3-0 = entry type
//  3. Cost (1 byte)
//  4. End date (4 bytes, seconds since epoch)
func (entry *MetaLeaseSetEntry) Bytes() ([]byte, error) {
	result := make([]byte, 0, META_LEASESET_ENTRY_SIZE)

	// Add hash (32 bytes)
	result = append(result, entry.hash[:]...)

	// Add flags (3 bytes)
	result = append(result, entry.flags[:]...)

	// Add cost (1 byte)
	result = append(result, entry.cost)

	// Add end_date (4 bytes)
	endDateBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(endDateBytes, entry.endDate)
	result = append(result, endDateBytes...)

	return result, nil
}
