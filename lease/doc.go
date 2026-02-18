// Package lease implements the I2P Lease and Lease2 common data structures
// according to specification version 0.9.67.
//
// A Lease defines the authorization for a particular tunnel to receive messages
// targeting a Destination. Each lease contains the SHA256 hash of the
// RouterIdentity of the gateway router, the tunnel identifier, and an
// expiration date that determines when the lease becomes invalid for message
// delivery.
//
// Two variants are supported:
//
//   - Lease: 44-byte structure with 8-byte millisecond-precision timestamps.
//     Used in the original LeaseSet structure.
//
//   - Lease2: 40-byte structure with 4-byte second-precision timestamps.
//     Introduced in specification 0.9.38 for LeaseSet2, EncryptedLeaseSet,
//     and MetaLeaseSet structures.
//
// Wire format (Lease, 44 bytes):
//
//	+----+----+----+----+----+----+----+----+
//	| tunnel_gw (32 bytes)                  |
//	+----+----+----+----+----+----+----+----+
//	| tunnel_id (4)     | end_date (8)      |
//	+----+----+----+----+----+----+----+----+
//
// Wire format (Lease2, 40 bytes):
//
//	+----+----+----+----+----+----+----+----+
//	| tunnel_gw (32 bytes)                  |
//	+----+----+----+----+----+----+----+----+
//	| tunnel_id (4)     | end_date (4)      |
//	+----+----+----+----+----+----+----+----+
//
// Constructors (NewLease, NewLease2) accept arbitrary timestamps and gateway
// hashes, including zero hashes and past times. Use Validate() or IsExpired()
// for semantic checks after construction. Parsing functions (ReadLease,
// ReadLease2) similarly perform no semantic validation, only structural parsing.
//
// Spec reference: https://geti2p.net/spec/common-structures#lease
package lease
