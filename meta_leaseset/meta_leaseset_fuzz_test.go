// Package meta_leaseset implements the I2P MetaLeaseSet common data structure
package meta_leaseset

import (
	"encoding/binary"
	"testing"
)

// FuzzReadMetaLeaseSet is a fuzz test for ReadMetaLeaseSet.
// It exercises the multi-step parser — destination, offline signature, options mapping,
// variable-count entries, variable-count revocations, and signature — to surface panic
// paths and length-underflow errors on arbitrary input.
func FuzzReadMetaLeaseSet(f *testing.F) {
	// Seed corpus: empty / too-short inputs
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(make([]byte, 100))
	f.Add(make([]byte, META_LEASESET_MIN_SIZE-1))

	// Seed corpus: well-formed minimal MetaLeaseSet with Ed25519 destination.
	// Destination: 384 zeros + KEY cert (type=5, len=4, sigType=7, cryptoType=0) = 391 bytes
	dest := make([]byte, 384)
	dest = append(dest,
		0x05,       // cert type = KEY
		0x00, 0x04, // cert length = 4
		0x00, 0x07, // sig type = Ed25519 (7)
		0x00, 0x00, // crypto type = ElGamal (0)
	)

	// published (4 bytes)
	pub := make([]byte, 4)
	binary.BigEndian.PutUint32(pub, 1700000000)

	// expires (2 bytes), flags (2 bytes), empty options (2 bytes)
	header := []byte{0x02, 0x58, 0x00, 0x00, 0x00, 0x00}

	// num_entries=1, entry (40 bytes)
	entry := make([]byte, META_LEASESET_ENTRY_SIZE) // all zeros: type=unknown, cost=0
	entry[35] = 0x01                                // entry type bits 3-0 = 1 (LeaseSet)

	// numr=0, signature (64 bytes all-zero Ed25519)
	tail := make([]byte, 1+64)

	seed := make([]byte, 0, len(dest)+len(pub)+len(header)+1+len(entry)+len(tail))
	seed = append(seed, dest...)
	seed = append(seed, pub...)
	seed = append(seed, header...)
	seed = append(seed, byte(1))  // num_entries
	seed = append(seed, entry...) // single entry
	seed = append(seed, tail...)  // numr + sig 64B

	f.Add(seed)

	// Seed: two entries, one revocation
	entry2 := make([]byte, META_LEASESET_ENTRY_SIZE)
	entry2[35] = 0x03 // type = LeaseSet2
	rev := make([]byte, META_LEASESET_REVOCATION_HASH_SIZE)
	seed2 := make([]byte, 0)
	seed2 = append(seed2, dest...)
	seed2 = append(seed2, pub...)
	seed2 = append(seed2, header...)
	seed2 = append(seed2, 0x02)
	seed2 = append(seed2, entry...)
	seed2 = append(seed2, entry2...)
	seed2 = append(seed2, 0x01) // numr
	seed2 = append(seed2, rev...)
	seed2 = append(seed2, make([]byte, 64)...)
	f.Add(seed2)

	f.Fuzz(func(t *testing.T, data []byte) {
		// ReadMetaLeaseSet must never panic, regardless of input.
		mls, remainder, err := ReadMetaLeaseSet(data)
		if err != nil {
			// Errors are expected for malformed data — just verify no panic.
			return
		}
		// If parsing succeeded, exercise accessors to confirm no nil-pointer panics.
		_ = mls.NumEntries()
		_ = mls.HasOfflineKeys()
		_ = mls.IsUnpublished()
		_ = mls.IsBlinded()
		_ = mls.Flags()
		_ = mls.Entries()
		_ = mls.Revocations()
		_ = remainder

		// Bytes() must also not panic on a successfully parsed structure.
		_, _ = mls.Bytes()
	})
}
