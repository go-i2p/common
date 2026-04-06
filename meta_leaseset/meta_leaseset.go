// Package meta_leaseset implements the I2P MetaLeaseSet common data structure
package meta_leaseset

import (
	"encoding/binary"
	"sort"
	"time"

	rootcommon "github.com/go-i2p/common"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ApplyCommonFields stores the parsed common header fields into the MetaLeaseSet,
// satisfying the rootcommon.LeaseSetFieldApplier interface to eliminate
// duplicated field assignment code shared with LeaseSet2.
func (mls *MetaLeaseSet) ApplyCommonFields(fields rootcommon.LeaseSetCommonFields) {
	mls.destination = fields.Destination
	mls.published = fields.Published
	mls.expires = fields.Expires
	mls.flags = fields.Flags
	mls.offlineSignature = fields.OfflineSignature
	mls.options = fields.Options
}

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
	log.WithFields(logger.Fields{"pkg": "meta_leaseset", "func": "ReadMetaLeaseSet"}).Debug("Parsing MetaLeaseSet structure")

	// Parse and apply common header fields shared with LeaseSet2
	data, err = rootcommon.ParseAndApplyCommonPrefix(&mls, data, META_LEASESET_MIN_SIZE, "MetaLeaseSet")
	if err != nil {
		return mls, remainder, err
	}

	log.WithFields(logger.Fields{
		"pkg":       "meta_leaseset",
		"func":      "ReadMetaLeaseSet",
		"published": mls.published,
		"expires":   mls.expires,
		"flags":     mls.flags,
	}).Debug("Parsed MetaLeaseSet header")

	// Parse entries
	data, err = parseEntries(&mls, data)
	if err != nil {
		return mls, remainder, err
	}

	// Parse revocations (numr + revocation hashes)
	data, err = parseRevocations(&mls, data)
	if err != nil {
		return mls, remainder, err
	}

	// Parse signature and finalize
	remainder, err = parseSignatureAndFinalize(&mls, data)
	if err != nil {
		return mls, remainder, err
	}

	return mls, remainder, err
}

// parseEntries parses the MetaLeaseSet entries from the data.
// Returns remaining data after parsing or error if validation or parsing fails.
func parseEntries(mls *MetaLeaseSet, data []byte) ([]byte, error) {
	if len(data) < META_LEASESET_NUM_ENTRIES_SIZE {
		err := oops.
			Code("missing_entry_count").
			Errorf("insufficient data for entry count")
		log.WithFields(logger.Fields{
			"pkg":  "meta_leaseset",
			"func": "parseEntries",
			"at":   "parseEntries",
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
		"pkg":         "meta_leaseset",
		"func":        "parseEntries",
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
			"pkg":         "meta_leaseset",
			"func":        "validateEntryCount",
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
func validateEntryMinSize(entryIndex, dataLen int) error {
	if dataLen < META_LEASESET_ENTRY_SIZE {
		err := oops.
			Code("entry_too_short").
			With("entry_index", entryIndex).
			With("remaining_length", dataLen).
			With("minimum_required", META_LEASESET_ENTRY_SIZE).
			Errorf("insufficient data for entry %d", entryIndex)
		log.WithFields(logger.Fields{
			"pkg":         "meta_leaseset",
			"func":        "validateEntryMinSize",
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
		"pkg":         "meta_leaseset",
		"func":        "logParsedEntry",
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
			"pkg":         "meta_leaseset",
			"func":        "validateEntryType",
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
	defaultSigType := mls.destination.KeyCertificate.SigningPublicKeyType()

	signature, rem, err := rootcommon.ParseLeaseSetSignature(
		data, defaultSigType, mls.HasOfflineKeys(), mls.offlineSignature, "MetaLeaseSet",
	)
	if err != nil {
		return nil, err
	}
	mls.signature = signature

	log.WithFields(logger.Fields{
		"pkg":              "meta_leaseset",
		"func":             "parseSignatureAndFinalize",
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
	result, err := serializeHeader(mls)
	if err != nil {
		return nil, err
	}

	result, err = serializeOptions(result, mls)
	if err != nil {
		return nil, err
	}

	result, err = serializeEntries(result, mls)
	if err != nil {
		return nil, err
	}

	result = serializeRevocations(result, mls)
	result = append(result, mls.signature.Bytes()...)

	log.WithFields(logger.Fields{
		"pkg":             "meta_leaseset",
		"func":            "MetaLeaseSet.Bytes",
		"total_size":      len(result),
		"num_entries":     mls.numEntries,
		"has_offline_sig": mls.offlineSignature != nil,
		"options_count":   len(mls.options.Values()),
	}).Debug("Serialized MetaLeaseSet to bytes")

	return result, nil
}

// serializeHeader serializes the destination, timestamps, flags, and optional
// offline signature into the beginning of the wire format.
func serializeHeader(mls *MetaLeaseSet) ([]byte, error) {
	destBytes, err := mls.destination.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize destination: %w", err)
	}
	result := make([]byte, 0)
	result = append(result, destBytes...)
	result = rootcommon.AppendBigEndianUint32(result, mls.published)
	result = rootcommon.AppendBigEndianUint16(result, mls.expires)
	result = rootcommon.AppendBigEndianUint16(result, mls.flags)

	if mls.offlineSignature != nil {
		result = append(result, mls.offlineSignature.Bytes()...)
	}
	return result, nil
}

// serializeOptions appends the options mapping to the result in canonical
// key order for signature invariance per the I2P spec.
func serializeOptions(result []byte, mls *MetaLeaseSet) ([]byte, error) {
	if len(mls.options.Values()) > 0 {
		sortedOpts, sortErr := common.ValuesToMapping(mls.options.Values())
		if sortErr != nil {
			return nil, oops.Errorf("failed to sort options mapping: %w", sortErr)
		}
		return append(result, sortedOpts.Data()...), nil
	}
	return append(result, 0x00, 0x00), nil
}

// serializeEntries appends the entry count and each serialized entry to the result.
func serializeEntries(result []byte, mls *MetaLeaseSet) ([]byte, error) {
	result = append(result, mls.numEntries)
	for i, entry := range mls.entries {
		entryBytes, err := entry.Bytes()
		if err != nil {
			return nil, oops.Wrapf(err, "failed to serialize entry %d", i)
		}
		result = append(result, entryBytes...)
	}
	return result, nil
}

// serializeRevocations appends the revocation count and hashes to the result.
func serializeRevocations(result []byte, mls *MetaLeaseSet) []byte {
	result = append(result, mls.numRevocations)
	for _, hash := range mls.revocations {
		result = append(result, hash[:]...)
	}
	return result
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
	result = rootcommon.AppendBigEndianUint32(result, entry.endDate)

	return result, nil
}
