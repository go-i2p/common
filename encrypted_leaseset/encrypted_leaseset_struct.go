// Package encrypted_leaseset implements the I2P EncryptedLeaseSet common data structure
package encrypted_leaseset

import (
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
)

// EncryptedLeaseSet represents an encrypted I2P LeaseSet2 (Database Store Type 5).
//
// Wire Format (I2P spec 0.9.67 — https://geti2p.net/spec/common-structures#encryptedleaseset):
//
//	sig_type            (2 bytes)   — Signing key type for the blinded public key
//	blinded_public_key  (variable)  — Blinded signing public key (length from sig_type)
//	published           (4 bytes)   — Timestamp in seconds since Unix epoch
//	expires             (2 bytes)   — Expiration offset from published in seconds
//	flags               (2 bytes)   — Bit 0: offline keys, Bit 1: unpublished, Bits 15‑2: reserved (0)
//	[offline_signature] (variable)  — Present only if flags bit 0 is set
//	len                 (2 bytes)   — Length of encrypted inner data
//	encrypted_data      (len bytes) — Encrypted LeaseSet2 structure
//	signature           (variable)  — Signature by blinded key or transient key (length from sig_type)
//
// NOTE: This structure does NOT use the LeaseSet2Header. There is no options mapping
// and no cookie in the cleartext wire format; those are internal to the encryption layer.
type EncryptedLeaseSet struct {
	// sig_type — identifies the signing key algorithm for the blinded public key.
	sigType uint16

	// blinded_public_key — the blinded signing public key bytes.
	blindedPublicKey []byte

	// published — seconds since Unix epoch.
	published uint32

	// expires — offset in seconds from published.
	expires uint16

	// flags — bit 0: offline keys, bit 1: unpublished, bits 15‑2: reserved.
	flags uint16

	// offlineSignature — present when flags bit 0 is set.
	offlineSignature *offline_signature.OfflineSignature

	// innerLength — length of encrypted inner data.
	innerLength uint16

	// encryptedInnerData — the encrypted LeaseSet2 payload.
	encryptedInnerData []byte

	// signature — over all preceding data prepended with DBSTORE type byte (0x05).
	signature sig.Signature
}
