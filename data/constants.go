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

// MAPPING_MIN_SIZE is the minimum size in bytes for a valid I2P mapping (2-byte length field + at least 1 byte data)
// Cross-Ref: mapping.go
const MAPPING_MIN_SIZE = 3

// MAPPING_SIZE_FIELD_LENGTH is the length in bytes of the mapping size field in I2P mappings
// Cross-Ref: mapping.go
const MAPPING_SIZE_FIELD_LENGTH = 2

// BITS_PER_BYTE is the number of bits in a byte, used for bit shift calculations
// Cross-Ref: integer.go
const BITS_PER_BYTE = 8
