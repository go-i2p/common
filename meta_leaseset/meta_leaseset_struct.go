// Package meta_leaseset implements the I2P MetaLeaseSet common data structure
package meta_leaseset

import (
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
)

/*
[MetaLeaseSet]
Accurate for version 0.9.67

Description:
Contained in a I2NP DatabaseStore message of type 7. Supported as of 0.9.38.
Aggregates multiple destinations under a single network database entry, enabling
load balancing, redundancy, and service migration. Each entry references another
lease set by hash and includes metadata for routing decisions.

A MetaLeaseSet is one of the structures stored in the network database,
and is keyed under the SHA256 of the contained Destination.

Contents:
Destination, published timestamp, expires offset, flags, optional offline signature,
options mapping, number of entries, entries (hash, flags, cost, end_date),
number of revocations, revocation hashes, and signature.

Wire Format:
+----+----+----+----+----+----+----+----+
| destination                           |
+                                       +
|                                       |
~        (387+ bytes)                   ~
|                                       |
+----+----+----+----+----+----+----+----+
|          published (4 bytes)          |
+----+----+----+----+----+----+----+----+
| expires (2) |    flags (2)            |
+----+----+----+----+----+----+----+----+
| [offline_signature]                   |
~        (variable, if flag set)        ~
|                                       |
+----+----+----+----+----+----+----+----+
|          options (2+ bytes)           |
~        (Mapping)                      ~
|                                       |
+----+----+----+----+----+----+----+----+
|num | Entry 0:                         |
+----+                                  +
|          hash (32 bytes)              |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|    flags (3 bytes)    |cost|          |
+----+----+----+----+----+----+----+----+
|      end_date (4 bytes)               |
+----+----+----+----+----+----+----+----+
| Entry 1 ... Entry (num-1)             |
~        (same format, 40 bytes each)   ~
|                                       |
+----+----+----+----+----+----+----+----+
|numr| revocation hashes (32 bytes ea.) |
~        (numr * 32 bytes)              ~
|                                       |
+----+----+----+----+----+----+----+----+
|          signature                    |
~        (variable, based on sigtype)   ~
|                                       |
+----+----+----+----+----+----+----+----+

destination :: Destination
               length -> 387+ bytes

published :: Integer
             length -> 4 bytes
             Seconds since Unix epoch (1970-01-01 00:00:00 UTC)

expires :: Integer
           length -> 2 bytes
           Offset from published timestamp in seconds.
           Maximum value is 65535 (18.2 hours).

flags :: Integer
         length -> 2 bytes
         Bit 0: offline keys (if set, offline signature follows)
         Bit 1: unpublished (should not be flooded to netdb)
         Other bits: reserved, must be 0

offline_signature :: OfflineSignature
                     length -> variable
                     Only present if flags bit 0 is set

options :: Mapping
           length -> 2+ bytes minimum
           Service record options for DNS-SD style service discovery.
           Options MUST be sorted by key for signature invariance.

num :: Integer
       length -> 1 byte
       Number of entries to follow
       value: 1 <= num <= 16

entries :: [MetaLease]
           length -> 40 bytes per entry
           Each entry is a fixed 40-byte MetaLease structure:
             hash (32 bytes) + flags (3 bytes) + cost (1 byte) + end_date (4 bytes)
           Flags bits 3-0 encode entry type: 0=unknown, 1=LeaseSet, 3=LeaseSet2, 5=MetaLeaseSet

numr :: Integer
        length -> 1 byte
        Number of revocation hashes to follow

revocations :: [Hash]
              length -> numr * 32 bytes
              SHA256 hashes of revoked lease sets

signature :: Signature
             length -> 40+ bytes (varies based on signature type)
             Signature over the data above, PREPENDED with the single byte
             containing the DatabaseStore type (7).

Notes:
- The signature is over the data above, PREPENDED with the single byte containing
  the DatabaseStore type (7).
- Each entry references another lease set by its SHA256 hash.
- Entry types can be unknown (0), LeaseSet (1), LeaseSet2 (3), or MetaLeaseSet (5).
- Entries are not required to be sorted; clients should use cost for selection.
- The options mapping must be sorted by key for signature invariance.
- Entry properties mappings must also be sorted by key.

https://geti2p.net/spec/common-structures#metaleaseset
*/

// MetaLeaseSet represents an I2P MetaLeaseSet structure introduced in specification 0.9.38.
// MetaLeaseSet aggregates multiple destinations under a single network database entry, enabling:
//   - Load balancing across multiple service endpoints
//   - Geographic distribution of service instances
//   - Service redundancy and failover capabilities
//   - Gradual migration between different lease set types
//   - Extended expiration up to 18.2 hours (vs 11 minutes for LeaseSet2)
//
// https://geti2p.net/spec/common-structures#metaleaseset
type MetaLeaseSet struct {
	destination      destination.Destination             // Destination identity (387+ bytes)
	published        uint32                              // Published timestamp (4 bytes, seconds since epoch)
	expires          uint16                              // Expiration offset from published (2 bytes, seconds, up to 18.2 hours)
	flags            uint16                              // Flags field (2 bytes) - subset of LeaseSet2 flags
	offlineSignature *offline_signature.OfflineSignature // Optional offline signature (present if flags bit 0 set)
	options          common.Mapping                      // Options mapping for service discovery (2+ bytes, sorted by key)
	numEntries       uint8                               // Number of lease set entries (1 byte, 1-16)
	entries          []MetaLeaseSetEntry                 // Lease set entries referencing other lease sets
	numRevocations   uint8                               // Number of revocation hashes (1 byte, per spec)
	revocations      [][32]byte                          // Revocation hashes (32 bytes each)
	signature        sig.Signature                       // Signature by destination or transient key
}

// MetaLeaseSetEntry represents a single MetaLease entry in a MetaLeaseSet.
// Per the I2P specification, each MetaLease is exactly 40 bytes:
//
//	hash(32) + flags(3) + cost(1) + end_date(4)
//
// The flags field encodes the entry type in bits 3-0:
//
//	0 = unknown, 1 = LeaseSet, 3 = LeaseSet2, 5 = MetaLeaseSet
//
// https://geti2p.net/spec/common-structures#metalease
type MetaLeaseSetEntry struct {
	// hash is the SHA256 hash of the referenced lease set (32 bytes).
	// The I2P spec names this field "tunnel_gw" (inherited from Lease2), but in
	// MetaLease it is repurposed to identify the referenced lease set rather
	// than a gateway router.
	hash    [32]byte
	flags   [3]byte // Flags (3 bytes): bits 3-0 = entry type, bits 23-4 reserved
	cost    uint8   // Cost metric for load balancing (1 byte, lower is better)
	endDate uint32  // Expiration timestamp (4 bytes, seconds since epoch)
}
