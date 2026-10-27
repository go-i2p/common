package common

// I2P_SPEC_VERSION defines the I2P specification version that this library implements.
// This constant should be updated whenever the implementation is updated to match a newer specification.
// Reference: https://geti2p.net/en/docs/specs/
//
// The common-structures page moved from accurateFor 0.9.68 to 0.9.71
// (lastUpdated 2026-10, i2p.website commit 12de4e69c). That revision changed no
// wire format: it added status annotations to four section descriptions -
// "DEPRECATED. Use LeaseSet2 and Lease2." on Lease and LeaseSet, and
// "PRELIMINARY. Not fully supported." on MetaLease and MetaLeaseSet - and
// dropped the OfflineSignature note "scheduled to be working as of 0.9.40".
// The post-quantum ML-KEM crypto types (5/6/7) and reserved MLDSA signing types
// (12-20) that this library models were already documented at 0.9.67/0.9.68, so
// this is a version alignment, not a behavioral change. The new annotations are
// documentation-only: the deprecated and preliminary structures remain fully
// implemented, since peers still publish them.
const I2P_SPEC_VERSION = "0.9.71"

// I2P_SPEC_MAJOR represents the major version component of the I2P specification.
const I2P_SPEC_MAJOR = 0

// I2P_SPEC_MINOR represents the minor version component of the I2P specification.
const I2P_SPEC_MINOR = 9

// I2P_SPEC_PATCH represents the patch version component of the I2P specification.
const I2P_SPEC_PATCH = 71
