// Package key_certificate implements the I2P Destination common data structure
package key_certificate

// Key Certificate Signing Key Types
const (
	KEYCERT_SIGN_DSA_SHA1  = 0
	KEYCERT_SIGN_P256      = 1
	KEYCERT_SIGN_P384      = 2
	KEYCERT_SIGN_P521      = 3
	KEYCERT_SIGN_RSA2048   = 4
	KEYCERT_SIGN_RSA3072   = 5
	KEYCERT_SIGN_RSA4096   = 6
	KEYCERT_SIGN_ED25519   = 7
	KEYCERT_SIGN_ED25519PH = 8
)

// Key Certificate Public Key Types
const (
	KEYCERT_CRYPTO_ELG    = 0
	KEYCERT_CRYPTO_P256   = 1
	KEYCERT_CRYPTO_P384   = 2
	KEYCERT_CRYPTO_P521   = 3
	KEYCERT_CRYPTO_X25519 = 4
)

// Minimum size constants
const (
	KEYCERT_MIN_SIZE = 7
)

// signingPublicKey sizes for Signing Key Types
const (
	KEYCERT_SIGN_DSA_SHA1_SIZE  = 128
	KEYCERT_SIGN_P256_SIZE      = 64
	KEYCERT_SIGN_P384_SIZE      = 96
	KEYCERT_SIGN_P521_SIZE      = 132
	KEYCERT_SIGN_RSA2048_SIZE   = 256
	KEYCERT_SIGN_RSA3072_SIZE   = 384
	KEYCERT_SIGN_RSA4096_SIZE   = 512
	KEYCERT_SIGN_ED25519_SIZE   = 32
	KEYCERT_SIGN_ED25519PH_SIZE = 32
)

// publicKey sizes for Public Key Types
const (
	KEYCERT_CRYPTO_ELG_SIZE    = 256
	KEYCERT_CRYPTO_P256_SIZE   = 64
	KEYCERT_CRYPTO_P384_SIZE   = 96
	KEYCERT_CRYPTO_P521_SIZE   = 132
	KEYCERT_CRYPTO_X25519_SIZE = 32
)

// Sizes of structures in KeyCertificates
const (
	KEYCERT_PUBKEY_SIZE = 256
	KEYCERT_SPK_SIZE    = 128
)

// Additional crypto and signature type constants
const (
	CRYPTO_KEY_TYPE_ELGAMAL = 0 // ElGamal

	// Signature Types
	SIGNATURE_TYPE_DSA_SHA1       = 0 // DSA-SHA1
	SIGNATURE_TYPE_ED25519_SHA512 = 7 // Ed25519
)
