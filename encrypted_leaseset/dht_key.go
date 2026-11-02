package encrypted_leaseset

import (
	"github.com/go-i2p/common/data"
)

// BlindedDHTKey computes the DHT storage/lookup key for an EncryptedLeaseSet.
//
// Per the EncryptedLeaseSet spec ("Format" section):
//
//	DHT storage location is SHA-256(sig type || blinded public key), and
//	rotated daily.
//
// The sig type is the 2-byte big-endian blinded signing key type (always 11,
// RedDSA, for a blinded record) carried in the Layer 0 header -- NOT the outer
// DatabaseStore "Type" byte (5), which the spec explicitly notes is "not
// actually in header". Hashing the blinded public key alone (a previous go-i2p
// behavior) is self-consistent but does not match Java/i2pd, so records
// published with the bare-key hash are invisible to a spec-following floodfill.
//
// "Rotated daily" is achieved by the blinded public key itself being per-day
// (derived from the day's blinding factor), so the caller supplies the current
// day's key; this function is a pure hash of the two fields.
func BlindedDHTKey(sigType uint16, blindedPublicKey []byte) data.Hash {
	// sig type (2 bytes, big endian) || blinded public key
	buf := make([]byte, 0, 2+len(blindedPublicKey))
	buf = appendUint16BE(buf, sigType)
	buf = append(buf, blindedPublicKey...)
	return data.HashData(buf)
}

// DHTKey returns the DHT storage/lookup key for this EncryptedLeaseSet, using
// its own sig type and blinded public key. See BlindedDHTKey for the rule.
func (els *EncryptedLeaseSet) DHTKey() data.Hash {
	return BlindedDHTKey(els.sigType, els.blindedPublicKey)
}

// appendUint16BE appends v as 2 bytes big endian.
func appendUint16BE(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}
