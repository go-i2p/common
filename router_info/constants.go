package router_info

// ROUTER_INFO_MIN_SIZE defines the minimum size of a RouterInfo structure in bytes.
// Derivation: RouterIdentity(387) + Date(8) + size(1) + peer_size(1) + Mapping(2 min) + Signature(40 DSA-SHA1 default) = 439
const ROUTER_INFO_MIN_SIZE = 439

// MIN_GOOD_VERSION defines the minimum acceptable patch version for the 0.9.x series.
// This mirrors Java I2P's RouterVersion.MIN_GOOD_VERSION. Version 0.9.58 is the
// Ed25519-mandate release where DSA_SHA1 was deprecated. Routers below this
// version are considered too old to interoperate safely.
const MIN_GOOD_VERSION = 58

// MAX_GOOD_VERSION defines the maximum acceptable patch version for the 0.9.x series.
// Set to 99 as an upper bound for the 0.9.x versioning scheme. When I2P
// transitions to a new major/minor version (e.g. 1.0.0), this validation logic
// and the associated validateMajorVersion/validateMinorVersion functions will
// need to be updated to accommodate the new version format.
const MAX_GOOD_VERSION = 99

// ============ Network Protocol Constants ============

// I2P_NETWORK_NAME is the network identifier returned by the Network() method
// implementing net.Addr interface for I2P router addresses
const I2P_NETWORK_NAME = "i2p"

// ============ Cryptographic Key Size Constants ============

// ED25519_PRIVATE_KEY_SIZE is the size in bytes of an Ed25519 private key
// Used for validation when creating Ed25519 signers in router info operations
const ED25519_PRIVATE_KEY_SIZE = 64
