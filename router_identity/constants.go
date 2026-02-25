// Package router_identity implements the I2P RouterIdentity common data structure
package router_identity

import "github.com/go-i2p/common/key_certificate"

// RouterIdentity-specific key type restrictions per I2P specification 0.9.67.
// https://geti2p.net/spec/common-structures#routeridentity

// Disallowed signing key types for Router Identities.
// Per spec:
//   - RedDSA (type 11): "For Destinations and encrypted leasesets only; never used for Router Identities."
//   - RSA types (4-6): "Offline only; never used in Key Certificates for Router Identities or Destinations."
//   - Ed25519ph (type 8): Offline/transient use only; not for Router Identity Key Certificates.
var disallowedSigningKeyTypes = map[int]string{
	key_certificate.KEYCERT_SIGN_RSA2048:        "RSA-2048 (offline only, not for Router Identities)",
	key_certificate.KEYCERT_SIGN_RSA3072:        "RSA-3072 (offline only, not for Router Identities)",
	key_certificate.KEYCERT_SIGN_RSA4096:        "RSA-4096 (offline only, not for Router Identities)",
	key_certificate.KEYCERT_SIGN_ED25519PH:      "Ed25519ph (offline only, not for Router Identities)",
	key_certificate.KEYCERT_SIGN_REDDSA_ED25519: "RedDSA (Destinations/encrypted leasesets only, not for Router Identities)",
}

// Disallowed crypto key types for Router Identities.
// Per spec (0.9.67):
//   - MLKEM hybrid types (5-7): "for Leasesets only, not for RIs or Destinations."
var disallowedCryptoKeyTypes = map[int]string{
	key_certificate.KEYCERT_CRYPTO_MLKEM512_X25519:  "MLKEM512+X25519 (LeaseSet only, not for Router Identities)",
	key_certificate.KEYCERT_CRYPTO_MLKEM768_X25519:  "MLKEM768+X25519 (LeaseSet only, not for Router Identities)",
	key_certificate.KEYCERT_CRYPTO_MLKEM1024_X25519: "MLKEM1024+X25519 (LeaseSet only, not for Router Identities)",
}

// ECDSA types (P256=1, P384=2, P521=3) are NOT in the disallow lists.
// The spec marks them as "Deprecated — Rarely if ever used for Destinations" but does not
// prohibit them for Router Identities.  ECDSA-P521 (132-byte key) requires excess signing-key
// data in the Key Certificate payload; this reconstruction is now supported by
// keys_and_cert.ReadKeysAndCert (see keys_and_cert/AUDIT.md, SPEC finding, FIXED).
// P256 (64 B) and P384 (96 B) fit fully in the 128-byte inline SPK field and parse cleanly.

// Deprecated key types for Router Identities.
// Per spec (0.9.58):
//   - ElGamal (crypto type 0): deprecated for Router Identities
//   - DSA-SHA1 (signing type 0): deprecated for Router Identities
const (
	DEPRECATED_CRYPTO_ELGAMAL   = key_certificate.KEYCERT_CRYPTO_ELG
	DEPRECATED_SIGNING_DSA_SHA1 = key_certificate.KEYCERT_SIGN_DSA_SHA1
)
