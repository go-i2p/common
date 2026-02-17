// Package router_address implements the I2P RouterAddress common data structure
package router_address

// ROUTER_ADDRESS_MIN_SIZE defines the minimum number of bytes in a valid RouterAddress.
// 1 (cost) + 8 (expiration) + 1 (transport_style length byte) + 2 (mapping size field) = 12.
const (
	ROUTER_ADDRESS_MIN_SIZE = 12
)

// ============ IP Version Constants ============

// IPV4_VERSION_STRING is the string representation for IPv4 addresses
const IPV4_VERSION_STRING = "4"

// IPV6_VERSION_STRING is the string representation for IPv6 addresses
const IPV6_VERSION_STRING = "6"

// IPV6_SUFFIX is the suffix used to identify IPv6 addresses in capabilities
const IPV6_SUFFIX = "6"

// ============ Transport Protocol Constants ============

// SSU_TRANSPORT_PREFIX is the prefix used to identify SSU (UDP-based) transports
const SSU_TRANSPORT_PREFIX = "ssu"

// ============ Router Address Option Keys ============

// HOST_OPTION_KEY is the mapping key for the host address option
const HOST_OPTION_KEY = "host"

// PORT_OPTION_KEY is the mapping key for the port number option
const PORT_OPTION_KEY = "port"

// CAPS_OPTION_KEY is the mapping key for the capabilities option
const CAPS_OPTION_KEY = "caps"

// STATIC_KEY_OPTION_KEY is the mapping key for the static key option
const STATIC_KEY_OPTION_KEY = "s"

// INITIALIZATION_VECTOR_OPTION_KEY is the mapping key for the initialization vector option
const INITIALIZATION_VECTOR_OPTION_KEY = "i"

// PROTOCOL_VERSION_OPTION_KEY is the mapping key for the protocol version option
const PROTOCOL_VERSION_OPTION_KEY = "v"

// INTRODUCER_HASH_PREFIX is the prefix for introducer hash option keys
const INTRODUCER_HASH_PREFIX = "ih"

// INTRODUCER_EXPIRATION_PREFIX is the prefix for introducer expiration option keys
const INTRODUCER_EXPIRATION_PREFIX = "iexp"

// INTRODUCER_TAG_PREFIX is the prefix for introducer tag option keys
const INTRODUCER_TAG_PREFIX = "itag"

// ============ Cryptographic Size Constants ============

// STATIC_KEY_SIZE is the size in bytes of a static key used in router addresses
const STATIC_KEY_SIZE = 32

// INITIALIZATION_VECTOR_SIZE is the size in bytes of an initialization vector
const INITIALIZATION_VECTOR_SIZE = 16

// ============ Introducer Limits ============

// MIN_INTRODUCER_NUMBER is the minimum valid introducer number
const MIN_INTRODUCER_NUMBER = 0

// MAX_INTRODUCER_NUMBER is the maximum valid introducer number
const MAX_INTRODUCER_NUMBER = 2

// DEFAULT_INTRODUCER_NUMBER is the default introducer number when out of range
const DEFAULT_INTRODUCER_NUMBER = 0
