// Package meta_leaseset implements the I2P MetaLeaseSet common data structure
package meta_leaseset

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// MakeEntryFlags creates a 3-byte flags field with the given entry type in bits 3-0.
// All other flag bits are set to zero.
// Per spec: flags byte[2] bits 3-0 encode the entry type.
func MakeEntryFlags(entryType uint8) [3]byte {
	return [3]byte{0, 0, entryType & 0x0F}
}

// parseRevocations parses the revocation section: numr (1 byte) + numr * 32-byte hashes.
// Per the I2P MetaLeaseSet spec, this section appears between entries and signature.
// Returns remaining data after parsing or error if insufficient data.
func parseRevocations(mls *MetaLeaseSet, data []byte) ([]byte, error) {
	if len(data) < META_LEASESET_NUM_REVOCATIONS_SIZE {
		err := oops.
			Code("missing_revocation_count").
			Errorf("insufficient data for revocation count")
		log.WithFields(logger.Fields{
			"at": "parseRevocations",
		}).Error(err.Error())
		return nil, err
	}

	numRevocations := uint8(data[0])
	data = data[META_LEASESET_NUM_REVOCATIONS_SIZE:]

	mls.numRevocations = numRevocations

	requiredBytes := int(numRevocations) * META_LEASESET_REVOCATION_HASH_SIZE
	if len(data) < requiredBytes {
		err := oops.
			Code("revocations_too_short").
			With("num_revocations", numRevocations).
			With("remaining_length", len(data)).
			With("required_bytes", requiredBytes).
			Errorf("insufficient data for %d revocation hashes", numRevocations)
		log.WithFields(logger.Fields{
			"at":               "parseRevocations",
			"num_revocations":  numRevocations,
			"remaining_length": len(data),
		}).Error(err.Error())
		return nil, err
	}

	mls.revocations = make([][32]byte, numRevocations)
	for i := 0; i < int(numRevocations); i++ {
		copy(mls.revocations[i][:], data[:META_LEASESET_REVOCATION_HASH_SIZE])
		data = data[META_LEASESET_REVOCATION_HASH_SIZE:]
	}

	log.WithFields(logger.Fields{
		"num_revocations": numRevocations,
	}).Debug("Parsed MetaLeaseSet revocations")

	return data, nil
}

// NumRevocations returns the number of revocation hashes in this MetaLeaseSet.
func (mls *MetaLeaseSet) NumRevocations() int {
	return int(mls.numRevocations)
}

// Revocations returns a copy of the revocation hashes.
func (mls *MetaLeaseSet) Revocations() [][32]byte {
	if len(mls.revocations) == 0 {
		return nil
	}
	result := make([][32]byte, len(mls.revocations))
	copy(result, mls.revocations)
	return result
}

// GetRevocation returns the revocation hash at the specified index.
// Returns error if index is out of range.
func (mls *MetaLeaseSet) GetRevocation(index int) ([32]byte, error) {
	if index < 0 || index >= len(mls.revocations) {
		return [32]byte{}, oops.
			Code("revocation_index_out_of_range").
			With("index", index).
			With("num_revocations", len(mls.revocations)).
			Errorf("revocation index %d out of range [0, %d)", index, len(mls.revocations))
	}
	return mls.revocations[index], nil
}
