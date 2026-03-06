// Package keys_and_cert implements the I2P KeysAndCert common data structure.
//
// KeysAndCert is a fundamental I2P structure consisting of an encryption public
// key, a signing public key, and a certificate. It is used as either a
// RouterIdentity or a Destination.
//
// The wire format is a fixed 384-byte data block (256-byte public key field +
// 128-byte signing public key field) followed by a variable-length certificate.
// When key types require fewer bytes than the field size, padding fills the gap.
// When signing keys exceed 128 bytes, the excess is stored in the Key
// Certificate payload per the I2P specification.
//
// Reference: https://geti2p.net/spec/common-structures#keysandcert
package keys_and_cert
