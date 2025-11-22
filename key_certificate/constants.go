// Package key_certificate implements the I2P Destination common data structure
package key_certificate

// Key Certificate Signing Key Types define the cryptographic signature algorithms
// supported by I2P Key Certificates for digital signature operations.
// These constants map to specific cryptographic algorithms as defined in I2P specification 0.9.67.
// https://geti2p.net/spec/common-structures#certificate

// Key Certificate Signing Key Types
const (
	// KEYCERT_SIGN_DSA_SHA1 identifies DSA with SHA-1 signature algorithm (type 0).
	// This is the legacy signature type used in early I2P implementations.
	// Deprecated for new router identities as of version 0.9.58 due to security concerns.
	KEYCERT_SIGN_DSA_SHA1 = 0

	// KEYCERT_SIGN_P256 identifies ECDSA-SHA256-P256 signature algorithm (type 1).
	// Uses NIST P-256 elliptic curve with SHA-256 hash function.
	// Provides 128-bit security level with 64-byte signatures.
	KEYCERT_SIGN_P256 = 1

	// KEYCERT_SIGN_P384 identifies ECDSA-SHA384-P384 signature algorithm (type 2).
	// Uses NIST P-384 elliptic curve with SHA-384 hash function.
	// Provides 192-bit security level with 96-byte signatures.
	KEYCERT_SIGN_P384 = 2

	// KEYCERT_SIGN_P521 identifies ECDSA-SHA512-P521 signature algorithm (type 3).
	// Uses NIST P-521 elliptic curve with SHA-512 hash function.
	// Provides 256-bit security level with 132-byte signatures.
	KEYCERT_SIGN_P521 = 3

	// KEYCERT_SIGN_RSA2048 identifies RSA-SHA256-2048 signature algorithm (type 4).
	// Uses 2048-bit RSA keys with SHA-256 hash function.
	// Primarily used for offline signing operations, rarely for router identities.
	KEYCERT_SIGN_RSA2048 = 4

	// KEYCERT_SIGN_RSA3072 identifies RSA-SHA384-3072 signature algorithm (type 5).
	// Uses 3072-bit RSA keys with SHA-384 hash function.
	// Enhanced security variant for offline signing operations.
	KEYCERT_SIGN_RSA3072 = 5

	// KEYCERT_SIGN_RSA4096 identifies RSA-SHA512-4096 signature algorithm (type 6).
	// Uses 4096-bit RSA keys with SHA-512 hash function.
	// Maximum security RSA variant for offline signing operations.
	KEYCERT_SIGN_RSA4096 = 6

	// KEYCERT_SIGN_ED25519 identifies EdDSA-SHA512-Ed25519 signature algorithm (type 7).
	// Uses Ed25519 Edwards curve with SHA-512 for high-performance signatures.
	// Current standard for router identities and destinations since I2P 0.9.15.
	KEYCERT_SIGN_ED25519 = 7

	// KEYCERT_SIGN_ED25519PH identifies EdDSA-SHA512-Ed25519ph signature algorithm (type 8).
	// Uses Ed25519ph (pre-hashed) variant with SHA-512 for large message efficiency.
	// Optimized for offline signing of large datasets.
	KEYCERT_SIGN_ED25519PH = 8
)

// Key Certificate Public Key Types define the cryptographic encryption algorithms
// supported by I2P Key Certificates for asymmetric encryption operations.
// These types determine the public key format and encryption capabilities.

// Key Certificate Public Key Types
const (
	// KEYCERT_CRYPTO_ELG identifies ElGamal encryption algorithm (type 0).
	// Traditional I2P encryption using 2048-bit ElGamal keys.
	// Used for legacy compatibility and session key exchange.
	KEYCERT_CRYPTO_ELG = 0

	// KEYCERT_CRYPTO_P256 identifies ECDH-P256 encryption algorithm (type 1).
	// Uses NIST P-256 elliptic curve for Elliptic Curve Diffie-Hellman key exchange.
	// Provides 128-bit security level with improved performance over ElGamal.
	KEYCERT_CRYPTO_P256 = 1

	// KEYCERT_CRYPTO_P384 identifies ECDH-P384 encryption algorithm (type 2).
	// Uses NIST P-384 elliptic curve for enhanced security key exchange.
	// Provides 192-bit security level for high-security applications.
	KEYCERT_CRYPTO_P384 = 2

	// KEYCERT_CRYPTO_P521 identifies ECDH-P521 encryption algorithm (type 3).
	// Uses NIST P-521 elliptic curve for maximum security key exchange.
	// Provides 256-bit security level for the most sensitive operations.
	KEYCERT_CRYPTO_P521 = 3

	// KEYCERT_CRYPTO_X25519 identifies X25519 encryption algorithm (type 4).
	// Uses Curve25519 for high-performance Elliptic Curve Diffie-Hellman.
	// Modern standard offering excellent security with optimized implementation.
	KEYCERT_CRYPTO_X25519 = 4
)

// Minimum size constants define the minimum byte requirements
// for valid Key Certificate structures to ensure proper parsing and validation.

// Minimum size constants
const (
	// KEYCERT_MIN_SIZE defines the minimum size in bytes for a valid Key Certificate.
	// This includes the certificate header, type fields, and minimal payload data.
	// Used for validation during certificate parsing to prevent buffer underruns.
	KEYCERT_MIN_SIZE = 7
)

// Signing public key size constants define the exact byte lengths
// for public keys used in different signature algorithms.
// These sizes are critical for proper key parsing and signature verification.

// signingPublicKey sizes for Signing Key Types
const (
	// KEYCERT_SIGN_DSA_SHA1_SIZE defines the size of DSA-SHA1 signing public keys (128 bytes).
	// Traditional DSA public key size for legacy signature verification.
	KEYCERT_SIGN_DSA_SHA1_SIZE = 128

	// KEYCERT_SIGN_P256_SIZE defines the size of ECDSA-P256 signing public keys (64 bytes).
	// Compact elliptic curve public key for efficient signature operations.
	KEYCERT_SIGN_P256_SIZE = 64

	// KEYCERT_SIGN_P384_SIZE defines the size of ECDSA-P384 signing public keys (96 bytes).
	// Enhanced security elliptic curve public key with larger key size.
	KEYCERT_SIGN_P384_SIZE = 96

	// KEYCERT_SIGN_P521_SIZE defines the size of ECDSA-P521 signing public keys (132 bytes).
	// Maximum security elliptic curve public key for highest protection level.
	KEYCERT_SIGN_P521_SIZE = 132

	// KEYCERT_SIGN_RSA2048_SIZE defines the size of RSA-2048 signing public keys (256 bytes).
	// Standard RSA public key size for offline signing operations.
	KEYCERT_SIGN_RSA2048_SIZE = 256

	// KEYCERT_SIGN_RSA3072_SIZE defines the size of RSA-3072 signing public keys (384 bytes).
	// Enhanced RSA public key size for improved security in offline operations.
	KEYCERT_SIGN_RSA3072_SIZE = 384

	// KEYCERT_SIGN_RSA4096_SIZE defines the size of RSA-4096 signing public keys (512 bytes).
	// Maximum RSA public key size for highest security offline signing.
	KEYCERT_SIGN_RSA4096_SIZE = 512

	// KEYCERT_SIGN_ED25519_SIZE defines the size of Ed25519 signing public keys (32 bytes).
	// Compact Edwards curve public key for high-performance signature verification.
	KEYCERT_SIGN_ED25519_SIZE = 32

	// KEYCERT_SIGN_ED25519PH_SIZE defines the size of Ed25519ph signing public keys (32 bytes).
	// Pre-hashed Ed25519 variant with same key size but optimized for large messages.
	KEYCERT_SIGN_ED25519PH_SIZE = 32
)

// Public key size constants define the exact byte lengths
// for encryption public keys used in different cryptographic algorithms.
// These sizes are essential for proper key parsing and encryption operations.

// publicKey sizes for Public Key Types
const (
	// KEYCERT_CRYPTO_ELG_SIZE defines the size of ElGamal public keys (256 bytes).
	// Traditional I2P encryption key size for ElGamal asymmetric encryption.
	KEYCERT_CRYPTO_ELG_SIZE = 256

	// KEYCERT_CRYPTO_P256_SIZE defines the size of ECDH-P256 public keys (64 bytes).
	// NIST P-256 elliptic curve public key for efficient key exchange operations.
	KEYCERT_CRYPTO_P256_SIZE = 64

	// KEYCERT_CRYPTO_P384_SIZE defines the size of ECDH-P384 public keys (96 bytes).
	// NIST P-384 elliptic curve public key for enhanced security key exchange.
	KEYCERT_CRYPTO_P384_SIZE = 96

	// KEYCERT_CRYPTO_P521_SIZE defines the size of ECDH-P521 public keys (132 bytes).
	// NIST P-521 elliptic curve public key for maximum security key exchange.
	KEYCERT_CRYPTO_P521_SIZE = 132

	// KEYCERT_CRYPTO_X25519_SIZE defines the size of X25519 public keys (32 bytes).
	// Curve25519 public key for high-performance Diffie-Hellman key exchange.
	KEYCERT_CRYPTO_X25519_SIZE = 32
)

// Key Certificate structure size constants define the standard sizes
// used in I2P Key Certificate operations for backward compatibility and parsing.

// Sizes of structures in KeyCertificates
const (
	// KEYCERT_PUBKEY_SIZE defines the standard public key field size in Key Certificates (256 bytes).
	// This is the legacy size used for ElGamal keys and maintained for compatibility.
	// Modern algorithms may use smaller keys but are padded to this size.
	KEYCERT_PUBKEY_SIZE = 256

	// KEYCERT_SPK_SIZE defines the standard signing public key field size in Key Certificates (128 bytes).
	// This is the legacy size used for DSA keys and maintained for compatibility.
	// Modern algorithms may use smaller keys but are padded to this size.
	KEYCERT_SPK_SIZE = 128
)

// Legacy cryptographic type constants maintained for backward compatibility
// with older I2P implementations and certificate parsing routines.

// Additional crypto and signature type constants
const (
	// CRYPTO_KEY_TYPE_ELGAMAL identifies ElGamal encryption for legacy compatibility (type 0).
	// This constant maintains compatibility with older certificate parsing code
	// that may reference the ElGamal algorithm by this alternative name.
	CRYPTO_KEY_TYPE_ELGAMAL = 0 // ElGamal

	// Signature type constants for legacy compatibility and external integrations.
	// These constants provide alternative names for signature algorithms to maintain
	// compatibility with different parts of the I2P codebase.

	// Signature Types
	// SIGNATURE_TYPE_DSA_SHA1 identifies DSA-SHA1 signatures for legacy compatibility (type 0).
	// Alternative constant name for DSA-SHA1 algorithm used in signature verification.
	SIGNATURE_TYPE_DSA_SHA1 = 0 // DSA-SHA1

	// SIGNATURE_TYPE_ED25519_SHA512 identifies Ed25519-SHA512 signatures (type 7).
	// Alternative constant name for Ed25519 algorithm used in modern I2P implementations.
	SIGNATURE_TYPE_ED25519_SHA512 = 7 // Ed25519
)
