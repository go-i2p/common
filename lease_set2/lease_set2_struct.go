// Package lease_set2 implements the I2P LeaseSet2 common data structure
package lease_set2

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
	"github.com/samber/oops"
)

/*
[LeaseSet2]
Accurate for version 0.9.67

Description:
Contained in a I2NP DatabaseStore message of type 3. Supported as of 0.9.38.
Contains all of the currently authorized Lease2 for a particular Destination,
and the PublicKey to which garlic messages can be encrypted. A LeaseSet is one
of the two structures stored in the network database (the other being RouterInfo),
and is keyed under the SHA256 of the contained Destination.

Contents:
LeaseSet2Header, followed by options, then one or more PublicKey for encryption,
Integer specifying how many Lease2 structures are in the set, followed by the
actual Lease2 structures and finally a Signature of the previous bytes signed by
the Destination's SigningPrivateKey or the transient key.

+----+----+----+----+----+----+----+----+
|         ls2_header                    |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|          options                      |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|numk| keytype0| keylen0 |              |
+----+----+----+----+----+              +
|          encryption_key_0             |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| keytypen| keylenn |                   |
+----+----+----+----+                   +
|          encryption_key_n             |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| num| Lease2 0                         |
+----+                                  +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| Lease2($num-1)                        |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| signature                             |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

ls2header :: LeaseSet2Header
             length -> varies (395+ bytes)

options :: Mapping
           length -> varies, 2 bytes minimum
           Service record options for DNS-SD style service discovery.
           Options MUST be sorted by key for signature invariance.

numk :: Integer
        length -> 1 byte
        Number of key types, key lengths, and PublicKeys to follow
        value: 1 <= numk <= 16 (implementation defined maximum)

keytype :: The encryption type of the PublicKey to follow.
           length -> 2 bytes
           See key_certificate package for encryption type constants.

keylen :: The length of the PublicKey to follow.
          Must match the specified length of the encryption type.
          length -> 2 bytes

encryption_key :: PublicKey
                  length -> keylen bytes

num :: Integer
       length -> 1 byte
       Number of Lease2s to follow
       value: 0 <= num <= 16

leases :: [Lease2]
          length -> $num*40 bytes

signature :: Signature
             length -> 40 bytes or as specified in destination's key certificate,
                       or by the sigtype of the transient public key, if present in the header

Notes:
- The signature is over the data above, PREPENDED with the single byte containing
  the DatabaseStore type (3).
- Encryption keys are in order of server preference, most-preferred first.
- For published leasesets, clients should honor server preference when selecting
  encryption method.
- The options mapping must be sorted by key for signature invariance.
- LeaseSet2 uses Lease2 structures (40 bytes) with 4-byte timestamps instead of
  legacy Lease structures (44 bytes) with 8-byte timestamps.

https://geti2p.net/spec/common-structures#leaseset2
*/

// LeaseSet2 represents an I2P LeaseSet2 structure introduced in specification 0.9.38.
// LeaseSet2 is the modern replacement for the legacy LeaseSet, providing enhanced features:
//   - Multiple encryption keys per leaseset for crypto agility
//   - More compact Lease2 structures with 4-byte timestamps
//   - Service record options for DNS-SD style service discovery
//   - Optional offline signature support for enhanced security
//   - Published timestamp field for better versioning
//
// https://geti2p.net/spec/common-structures#leaseset2
type LeaseSet2 struct {
	destination      destination.Destination             // Destination identity (387+ bytes)
	published        uint32                              // Published timestamp (4 bytes, seconds since epoch)
	expires          uint16                              // Expiration offset from published (2 bytes, seconds)
	flags            uint16                              // Flags field (2 bytes)
	offlineSignature *offline_signature.OfflineSignature // Optional offline signature (present if flags bit 0 set)
	options          common.Mapping                      // Options mapping for service records (2+ bytes, sorted by key)
	encryptionKeys   []EncryptionKey                     // Encryption keys (1-16 keys)
	leases           []lease.Lease2                      // Lease2 structures (0-16 leases)
	signature        sig.Signature                       // Signature by destination or transient key
}

// EncryptionKey represents a single encryption key entry in LeaseSet2.
// Each entry contains the key type, length, and the actual key data.
type EncryptionKey struct {
	KeyType uint16 // Encryption key type (2 bytes) - see key_certificate constants
	KeyLen  uint16 // Length of the key data (2 bytes)
	KeyData []byte // Encryption key data (keyLen bytes)
}

// Validate checks the structural integrity of the LeaseSet2.
// It verifies:
//   - At least 1 encryption key is present
//   - Encryption key count does not exceed maximum
//   - Each encryption key has consistent KeyLen and KeyData length
//   - Each encryption key's KeyLen matches the expected size for its KeyType
//   - Offline signature flag is consistent with OfflineSignature presence
//   - Reserved flag bits are zero
//
// Returns nil if valid, or an error describing the first issue found.
func (ls2 *LeaseSet2) Validate() error {
	if ls2 == nil {
		return oops.Errorf("LeaseSet2 is nil")
	}

	// Check encryption keys
	if len(ls2.encryptionKeys) < 1 {
		return oops.Errorf("LeaseSet2 must have at least 1 encryption key")
	}
	if len(ls2.encryptionKeys) > LEASESET2_MAX_ENCRYPTION_KEYS {
		return oops.Errorf("LeaseSet2 has too many encryption keys: %d (max %d)", len(ls2.encryptionKeys), LEASESET2_MAX_ENCRYPTION_KEYS)
	}

	// Validate each encryption key
	for i, key := range ls2.encryptionKeys {
		if err := validateEncryptionKeyConsistency(i, key); err != nil {
			return err
		}
	}

	// Validate offline signature flag consistency
	if ls2.HasOfflineKeys() && ls2.offlineSignature == nil {
		return oops.Errorf("OFFLINE_KEYS flag set but no offline signature present")
	}
	if !ls2.HasOfflineKeys() && ls2.offlineSignature != nil {
		return oops.Errorf("offline signature present but OFFLINE_KEYS flag not set")
	}

	// Check reserved flag bits
	reservedMask := uint16(0xFFF8)
	if ls2.flags&reservedMask != 0 {
		return oops.Errorf("LeaseSet2 has non-zero reserved flag bits: 0x%04x", ls2.flags&reservedMask)
	}

	// Validate lease count
	if len(ls2.leases) > LEASESET2_MAX_LEASES {
		return oops.Errorf("LeaseSet2 has too many leases: %d (max %d)", len(ls2.leases), LEASESET2_MAX_LEASES)
	}

	return nil
}

// validateEncryptionKeyConsistency checks that an encryption key's declared length
// matches both the actual data length and the expected size for its key type.
func validateEncryptionKeyConsistency(index int, key EncryptionKey) error {
	if int(key.KeyLen) != len(key.KeyData) {
		return oops.Errorf("encryption key %d: declared KeyLen %d does not match actual KeyData length %d",
			index, key.KeyLen, len(key.KeyData))
	}
	if expectedSize, ok := key_certificate.CryptoPublicKeySizes[key.KeyType]; ok {
		if int(key.KeyLen) != expectedSize {
			return oops.Errorf("encryption key %d: KeyLen %d does not match expected size %d for key type %d",
				index, key.KeyLen, expectedSize, key.KeyType)
		}
	}
	return nil
}

// IsValid returns true if the LeaseSet2 passes structural validation.
func (ls2 *LeaseSet2) IsValid() bool {
	return ls2.Validate() == nil
}
