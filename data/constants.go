package data

// DATE_SIZE is the length in bytes of an I2P Date.
// Cross-Ref: date.go
const DATE_SIZE = 8

// MAX_INTEGER_SIZE is the maximum length of an I2P integer in bytes.
// Cross-Ref: integer.go
const MAX_INTEGER_SIZE = 8

// STRING_MAX_SIZE is the maximum number of bytes that can be stored in an I2P string
// Cross-Ref: string.go
const STRING_MAX_SIZE = 255

// ============ I2P Protocol Constants ============

// MAPPING_EQUALS_DELIMITER is the ASCII character '=' (0x3d) used to separate keys from values in I2P mappings
// Cross-Ref: mapping.go
const MAPPING_EQUALS_DELIMITER = 0x3d

// MAPPING_SEMICOLON_DELIMITER is the ASCII character ';' (0x3b) used to separate key-value pairs in I2P mappings
// Cross-Ref: mapping.go
const MAPPING_SEMICOLON_DELIMITER = 0x3b

// KEY_VAL_INTEGER_LENGTH is the length in bytes for encoding key and value lengths in I2P mappings
// Cross-Ref: mapping.go
const KEY_VAL_INTEGER_LENGTH = 1

// MAPPING_MIN_SIZE is the minimum size in bytes for a valid I2P mapping (2-byte size field; size=0 is valid)
// Cross-Ref: mapping.go
const MAPPING_MIN_SIZE = 2

// MAPPING_SIZE_FIELD_LENGTH is the length in bytes of the mapping size field in I2P mappings
// Cross-Ref: mapping.go
const MAPPING_SIZE_FIELD_LENGTH = 2

// MAX_MAPPING_DATA_SIZE is the maximum number of bytes in a mapping's data payload.
// Per the I2P spec: "Total length limit is 65535 bytes, plus the 2 byte size field, or 65537 total."
// Cross-Ref: mapping_values.go
const MAX_MAPPING_DATA_SIZE = 65535

// MAX_MAPPING_PAIRS is the maximum number of key-value pairs allowed in a single mapping.
// The I2P spec imposes no pair-count limit; it bounds a Mapping by total size only:
// "Total length limit is 65535 bytes, plus the 2 byte size field, or 65537 total."
// The smallest legal pair is 4 bytes (1-byte zero key length + '=' + 1-byte zero
// value length + ';'), so the largest mapping the spec permits holds
// 65535/4 = 16383 pairs. Deriving the cap from that bound means it can never
// reject a specification-legal mapping, while still bounding the parse loop
// against pathological input.
// Cross-Ref: mapping_values.go
const MAX_MAPPING_PAIRS = MAX_MAPPING_DATA_SIZE / MIN_MAPPING_PAIR_SIZE // 16383

// MIN_MAPPING_PAIR_SIZE is the smallest number of bytes a key-value pair can
// occupy on the wire: 1 (key length byte, value 0) + 1 ('=') +
// 1 (value length byte, value 0) + 1 (';') = 4 bytes.
// Cross-Ref: mapping_values.go
const MIN_MAPPING_PAIR_SIZE = 4

// BITS_PER_BYTE is the number of bits in a byte, used for bit shift calculations
// Cross-Ref: integer.go
const BITS_PER_BYTE = 8
