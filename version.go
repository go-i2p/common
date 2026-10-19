// Package common provides I2P protocol common data structures and utilities.
package common

// I2P_SPEC_VERSION defines the I2P specification version that this library implements.
// This constant should be updated whenever the implementation is updated to match a newer specification.
// Reference: https://geti2p.net/en/docs/specs/
//
// The common-structures specification page was revised from 0.9.67 to 0.9.71
// (Updated: 2026-10). The 0.9.71 revision documents the post-quantum ML-KEM
// key types (5/6/7, "Total Public Key Length 32") and the reserved MLDSA
// signing types (12-20) that this library already models; the wire structures
// themselves are unchanged, so this is a documentation/version alignment, not
// a behavioral change.
const I2P_SPEC_VERSION = "0.9.71"

// I2P_SPEC_MAJOR represents the major version component of the I2P specification.
const I2P_SPEC_MAJOR = 0

// I2P_SPEC_MINOR represents the minor version component of the I2P specification.
const I2P_SPEC_MINOR = 9

// I2P_SPEC_PATCH represents the patch version component of the I2P specification.
const I2P_SPEC_PATCH = 71
