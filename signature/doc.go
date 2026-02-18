// Package signature implements the I2P Signature common data structure.
//
// A Signature represents the cryptographic signature of some data in the I2P
// network. Signature type and length are inferred from the type of key used.
//
// # Supported Signature Types
//
// The following signature algorithms are supported per the I2P specification:
//
//   - Type 0: DSA-SHA1 (40 bytes) — DEPRECATED
//   - Type 1: ECDSA-SHA256-P256 (64 bytes) — DEPRECATED
//   - Type 2: ECDSA-SHA384-P384 (96 bytes) — DEPRECATED
//   - Type 3: ECDSA-SHA512-P521 (132 bytes) — DEPRECATED
//   - Type 4: RSA-SHA256-2048 (256 bytes) — DEPRECATED
//   - Type 5: RSA-SHA384-3072 (384 bytes) — DEPRECATED
//   - Type 6: RSA-SHA512-4096 (512 bytes)
//   - Type 7: EdDSA-SHA512-Ed25519 (64 bytes) — RECOMMENDED
//   - Type 8: EdDSA-SHA512-Ed25519ph (64 bytes)
//   - Type 9: GOST R 34.10-2012-512 (64 bytes) — RESERVED (Proposal 134)
//   - Type 10: GOST R 34.10-2012-1024 (128 bytes) — RESERVED (Proposal 134)
//   - Type 11: RedDSA-SHA512-Ed25519 (64 bytes)
//   - Types 12-20: MLDSA post-quantum (RESERVED, Proposal 169)
//   - Types 65280-65534: Experimental (RESERVED)
//
// # Byte Order
//
// Per the I2P specification, all signature types are Big Endian, EXCEPT for
// EdDSA and RedDSA (types 7, 8, 11), which are stored and transmitted in
// Little Endian format. This package stores raw signature bytes as received
// and does not perform endian conversion.
//
// # Usage
//
//	sig, remainder, err := signature.ReadSignature(data, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
//	if err != nil {
//	    // handle error
//	}
//	fmt.Printf("Signature length: %d\n", sig.Len())
//
// Reference: https://geti2p.net/spec/common-structures#signature
package signature
