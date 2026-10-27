package meta_leaseset

import (
	"github.com/go-i2p/common/offline_signature"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Validate checks the internal consistency of the MetaLeaseSet against the
// structural requirements of the I2P common-structures specification.
//
// MetaLeaseSet begins with a LeaseSet2Header, so the header rules that
// LeaseSet2 enforces apply here as well:
//
//   - flags bits 15-3 must be zero ("set to 0 for compatibility with future uses")
//   - flags bit 0 must agree with the presence of an OfflineSignature
//   - the options mapping must be sorted by key for signature invariance
//   - at least one entry, and no more than META_LEASESET_MAX_ENTRIES
//   - each MetaLease entry's flags bits 23-4 must be zero
//
// https://geti2p.net/spec/common-structures#metaleaseset
//
// Like LeaseSet2, this is a strict outbound/caller-facing check. The parse path
// only warns, so that inbound data from other implementations is not discarded
// over a reserved bit (see the "Inbound Parsing vs. Outbound Publishing" note
// in the package documentation).
func (mls *MetaLeaseSet) Validate() error {
	if mls == nil {
		return oops.Errorf("MetaLeaseSet is nil")
	}
	if err := validateReservedFlags(mls.flags); err != nil {
		return err
	}
	if err := validateOfflineSignatureConsistency(mls.HasOfflineKeys(), mls.offlineSignature); err != nil {
		return err
	}
	if err := validateEntryCount(int(mls.numEntries)); err != nil {
		return err
	}
	if int(mls.numEntries) != len(mls.entries) {
		return oops.
			Code("entry_count_mismatch").
			With("declared", mls.numEntries).
			With("actual", len(mls.entries)).
			Errorf("MetaLeaseSet entry count %d does not match %d entries", mls.numEntries, len(mls.entries))
	}
	if int(mls.numRevocations) != len(mls.revocations) {
		return oops.
			Code("revocation_count_mismatch").
			With("declared", mls.numRevocations).
			With("actual", len(mls.revocations)).
			Errorf("MetaLeaseSet revocation count %d does not match %d revocations", mls.numRevocations, len(mls.revocations))
	}
	if err := validateEntriesReservedFlagBits(mls.entries); err != nil {
		return err
	}
	// Spec: the structure ends with a Signature over the preceding bytes; a
	// missing or empty signature would serialize a record peers cannot verify.
	if err := mls.signature.Validate(); err != nil {
		return oops.Wrapf(err, "MetaLeaseSet has an invalid signature")
	}
	// Spec: the options mapping must be sorted by key so the signature is invariant.
	return validateOptionsSorted(mls.options)
}

// IsValid reports whether Validate returns nil.
func (mls *MetaLeaseSet) IsValid() bool {
	return mls.Validate() == nil
}

// validateReservedFlags rejects non-zero values in LeaseSet2Header flag bits
// 15-3, which the specification reserves: "Bits 15-3: set to 0 for compatibility
// with future uses".
func validateReservedFlags(flags uint16) error {
	if flags&META_LEASESET_RESERVED_FLAGS_MASK != 0 {
		return oops.
			Code("reserved_flags_set").
			With("flags", flags).
			With("reserved_bits", flags&META_LEASESET_RESERVED_FLAGS_MASK).
			Errorf("MetaLeaseSet has non-zero reserved flag bits (bits 15-3): 0x%04x",
				flags&META_LEASESET_RESERVED_FLAGS_MASK)
	}
	return nil
}

// validateOfflineSignatureConsistency checks that flags bit 0 agrees with the
// presence of an OfflineSignature. Spec: the offline signature is "only present
// if bit 0 is set in the flags".
func validateOfflineSignatureConsistency(hasOfflineKeys bool, offlineSig *offline_signature.OfflineSignature) error {
	if hasOfflineKeys && offlineSig == nil {
		return oops.
			Code("missing_offline_signature").
			Errorf("OFFLINE_KEYS flag set but no offline signature present")
	}
	if !hasOfflineKeys && offlineSig != nil {
		return oops.
			Code("unexpected_offline_signature").
			Errorf("offline signature present but OFFLINE_KEYS flag not set")
	}
	return nil
}

// validateEntriesReservedFlagBits checks each MetaLease entry's 3-byte flags
// field. Spec: "Bits 3-0: Type of the entry... Bits 23-4: set to 0 for
// compatibility with future uses".
func validateEntriesReservedFlagBits(entries []MetaLeaseSetEntry) error {
	for i := range entries {
		if entries[i].flags[0] != 0 || entries[i].flags[1] != 0 || entries[i].flags[2]&0xF0 != 0 {
			return oops.
				Code("entry_reserved_flag_bits_set").
				With("entry_index", i).
				Errorf("MetaLease entry %d has non-zero reserved flag bits (bits 23-4): %x", i, entries[i].flags)
		}
	}
	return nil
}

// warnIfEntryReservedFlagBits logs non-zero MetaLease entry flag bits 23-4 on
// inbound data without rejecting it. The spec phrases those bits as a producer
// obligation ("set to 0 for compatibility with future uses"), and the raw bytes
// are preserved for round-trip, so an inbound entry that sets them is kept.
func warnIfEntryReservedFlagBits(entry *MetaLeaseSetEntry, entryIndex int) {
	if entry.flags[0] == 0 && entry.flags[1] == 0 && entry.flags[2]&0xF0 == 0 {
		return
	}
	log.WithFields(logger.Fields{
		"pkg":         "meta_leaseset",
		"func":        "parseSingleEntry",
		"entry_index": entryIndex,
		"flags":       entry.flags[:],
	}).Warn("MetaLease entry has non-zero reserved flag bits (bits 23-4 should be 0)")
}

// warnIfReservedFlagsSet logs the presence of reserved header bits on inbound
// data without rejecting it, matching the LeaseSet2 parse behaviour.
func warnIfReservedFlagsSet(flags uint16) {
	if flags&META_LEASESET_RESERVED_FLAGS_MASK == 0 {
		return
	}
	log.WithFields(logger.Fields{
		"pkg":           "meta_leaseset",
		"func":          "ReadMetaLeaseSet",
		"flags":         flags,
		"reserved_bits": flags & META_LEASESET_RESERVED_FLAGS_MASK,
	}).Warn("MetaLeaseSet has non-zero reserved flag bits (bits 15-3 should be 0)")
}
