// Package lease_set2 implements the I2P LeaseSet2 common data structure
// as specified in I2P specification 0.9.67.
//
// LeaseSet2 (DatabaseStore type 3, introduced in spec 0.9.38) is the modern
// replacement for the legacy LeaseSet, providing enhanced features including
// multiple encryption keys, compact Lease2 structures, service discovery
// options, and optional offline signature support.
//
// The package provides:
//   - Parsing via ReadLeaseSet2
//   - Construction via NewLeaseSet2
//   - Serialization via Bytes
//   - Signature verification via Verify
//   - Structural validation via Validate
//
// https://geti2p.net/spec/common-structures#leaseset2
package lease_set2
