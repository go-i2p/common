package router_info

// ROUTER_INFO_MIN_SIZE defines the minimum size of a RouterInfo structure in bytes.
const ROUTER_INFO_MIN_SIZE = 439

// MIN_GOOD_VERSION defines the minimum acceptable router version.
const MIN_GOOD_VERSION = 58

// MAX_GOOD_VERSION defines the maximum acceptable router version.
const MAX_GOOD_VERSION = 99

// ============ Network Protocol Constants ============

// I2P_NETWORK_NAME is the network identifier returned by the Network() method
// implementing net.Addr interface for I2P router addresses
const I2P_NETWORK_NAME = "i2p"

// ============ Cryptographic Key Size Constants ============

// ED25519_PRIVATE_KEY_SIZE is the size in bytes of an Ed25519 private key
// Used for validation when creating Ed25519 signers in router info operations
const ED25519_PRIVATE_KEY_SIZE = 64
