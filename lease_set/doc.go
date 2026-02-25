// Package lease_set implements the I2P LeaseSet v1 common data structure.
//
// # Overview
//
// A LeaseSet is one of two structures stored in the I2P network database
// (the other being RouterInfo). It bundles all currently authorized Leases
// for a particular Destination together with the ElGamal encryption public
// key for that Destination and is signed by the Destination's private signing
// key.
//
// The LeaseSet is keyed in the netdb under the SHA-256 hash of the Destination;
// call [LeaseSet.Hash] to obtain this key.
//
// # LeaseSet v1 vs. LeaseSet2
//
// This package implements LeaseSet v1 only. LeaseSet v1 mandates an ElGamal
// encryption key (256 bytes) and supports up to 16 leases. Destinations using
// non-ElGamal crypto (X25519, etc.) and the extended features introduced in
// I2P 0.9.38+ must use LeaseSet2 (see the lease_set2 package).
//
// # Versioning
//
// Floodfill routers use the earliest expiration of all contained [Lease]
// entries as the LeaseSet version. Call [LeaseSet.OldestExpiration] to
// obtain this value and compare it with a cached LeaseSet when deciding
// whether a received LeaseSet is newer.
//
// # Thread Safety
//
// LeaseSet values are immutable after construction. Concurrent reads are safe;
// no locking is required.
//
// # Spec reference
//
// https://geti2p.net/spec/common-structures#leaseset
package lease_set
