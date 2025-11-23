// Package lease_set2 implements the I2P LeaseSet2 common data structure
package lease_set2

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
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
