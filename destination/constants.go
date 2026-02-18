// Package destination implements the I2P Destination common data structure
package destination

// ============ I2P Address Generation Constants ============

// I2PBase32Suffix is the standard suffix for I2P base32 addresses.
// Used in destination address generation to create valid I2P hostnames.
const I2PBase32Suffix = ".b32.i2p"

// Deprecated: Use I2PBase32Suffix instead. This name does not follow Go conventions.
const I2P_BASE32_SUFFIX = I2PBase32Suffix
