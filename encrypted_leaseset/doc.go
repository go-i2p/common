// Package encrypted_leaseset implements the I2P EncryptedLeaseSet common data
// structure (Database Store Type 5).
//
// EncryptedLeaseSet provides encrypted and blinded lease sets for enhanced
// privacy in I2P hidden services. Introduced in I2P version 0.9.38, it addresses
// privacy concerns with traditional lease sets by:
//
//   - Encrypting destination and leases: the actual service destination and
//     tunnel endpoints are encrypted, protecting against traffic analysis.
//   - Blinded key derivation: each published EncryptedLeaseSet uses a blinded
//     signing key, preventing correlation between different publications of the
//     same service.
//   - Two-layer encryption: HKDF-SHA256 + ChaCha20 stream cipher with
//     per-publication random salts.
//   - Subcredential binding: encryption is bound to knowledge of the
//     destination's signing public key via a subcredential, so only clients who
//     know the original destination can decrypt.
//
// # Wire Format
//
// An EncryptedLeaseSet consists of the following cleartext outer fields:
//
//	sig_type            (2 bytes)   — Red25519 (11) or Ed25519 (7)
//	blinded_public_key  (variable)  — 32 bytes for Ed25519/Red25519
//	published           (4 bytes)   — seconds since Unix epoch
//	expires             (2 bytes)   — offset from published (seconds)
//	flags               (2 bytes)   — bit 0: offline sig; bit 1: unpublished; bits 2-15 reserved
//	[offline_signature] (variable)  — present only if flags bit 0 set
//	inner_length        (2 bytes)   — size of encrypted_data
//	encrypted_data      (variable)  — two-layer ChaCha20 encrypted LeaseSet2
//	signature           (variable)  — by blinded key or transient key
//
// This structure does NOT use the standard LeaseSet2Header; the Destination is
// not present in the header (it is blinded).
//
// # Encrypted Data Structure
//
// The encrypted_data field uses a two-layer ChaCha20 stream cipher scheme:
//
//	encrypted_data = outerSalt(32) || Layer1Ciphertext
//
//	Layer 1 plaintext = flag(1) || [per-client auth block] || innerCiphertext
//
//	innerCiphertext   = innerSalt(32) || Layer2Ciphertext
//
//	Layer 2 plaintext = type(1) || serialized inner lease set
//
// The Layer 2 type byte is defined by the specification as "Either 3 (LS2) or
// 7 (Meta LS2)"; EncryptInnerLeaseSet2 emits 3 and EncryptInnerMetaLeaseSet
// emits 7, and DecryptInnerLeaseSet dispatches on it. The byte is also the
// DatabaseStore prefix covered by the inner structure's own signature.
//
// The flag byte's bit 0 selects per-client authorization; when set, bits 3-1
// select the scheme (DH or PSK) and the auth block follows. When clear (auth
// type 0) no auth block is present.
//
// Key derivation:
//
//	Layer 1 key: HKDF-SHA256(outerSalt, subcredential || published, "ELS2_L1K", 44)
//	Layer 2 key: HKDF-SHA256(innerSalt, authCookie || subcredential || published, "ELS2_L2K", 44)
//
// For auth type 0, authCookie is the zero-length byte array, so the Layer 2
// input reduces to subcredential || published. Here
// subcredential = SHA-256("subcredential" || credential || blindedPubKey) and
// credential = SHA-256("credential" || destSigningPubKey || stA || stA').
//
// # Per-Client Authorization
//
// EncryptedLeaseSet supports restricting decryption to a list of authorized
// clients (I2P spec §"Per-client authorization"). A random 32-byte authCookie is
// generated per publication, encrypted to each authorized client, and folded
// into the Layer 2 key derivation (innerInput = authCookie || subcredential ||
// published). Only clients that can recover authCookie can decrypt the inner
// LeaseSet2.
//
// Two schemes are supported:
//
//   - DH (auth type 1, X25519): each client generates an X25519 keypair and
//     gives the server its public key. The server uses an ephemeral DH exchange
//     so the client's private key never leaves its device.
//   - PSK (auth type 2): each client shares a 32-byte pre-shared key with the
//     server out-of-band.
//
// The Layer 1 middle layer carries, after the 1-byte flag, either the ephemeral
// public key (DH) or salt (PSK), a 2-byte client count, and one 40-byte
// authClient entry per client (clientID(8) || clientCookie(32)).
//
// Encrypting with per-client authorization (server side):
//
//	// DH: collect each authorized client's X25519 public key (cpk_i).
//	cfg := &encrypted_leaseset.ClientAuthConfig{
//	    AuthType:           encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_DH,
//	    DHClientPublicKeys: [][]byte{clientPubKey1, clientPubKey2},
//	}
//	encryptedData, err := encrypted_leaseset.EncryptInnerLeaseSet2WithAuth(
//	    ls2, subcredential, published, cfg,
//	)
//
// Decrypting with a client credential (client side):
//
//	// DH: supply the client's X25519 private key (csk_i).
//	cred := &encrypted_leaseset.ClientCredential{
//	    AuthType:     encrypted_leaseset.ENCRYPTED_LEASESET_AUTH_TYPE_DH,
//	    DHPrivateKey: clientPrivKey,
//	}
//	innerLS2, err := els.DecryptInnerDataWithCredential(subcredential, cred)
//
// For PSK, set AuthType to ENCRYPTED_LEASESET_AUTH_TYPE_PSK and populate
// PSKClientKeys / PSK with the 32-byte pre-shared keys. For auth type 0 (no
// per-client authorization), pass cfg == nil / cred == nil, or use
// EncryptInnerLeaseSet2 / DecryptInnerData.
//
// # Cryptographic Primitives
//
// X25519 operations (key derivation and Diffie-Hellman) use the
// github.com/go-i2p/crypto/curve25519 package. ChaCha20 and HKDF-SHA256 follow
// the I2P encryptedleaseset specification.
//
// # Security Considerations
//
// The blinded signing key is derived from the destination's signing key using the
// specification's GENERATE_ALPHA() construction, in which the blinding factor is
// bound to the destination signing public key and signature type as well as the
// UTC date and optional secret. This provides unlinkability across publications
// while remaining verifiable by clients who know the destination, and matches the
// key material a spec-conforming peer derives. The blinded key is published with
// signature type 11 (Red25519) as the specification requires. The subcredential
// binds encryption to knowledge of the original destination's signing public key.
//
// # Signing

// Red25519 signing: the spec mandates randomized nonces for the blinded outer
// signature - "T = 80 random bytes; r = H*(T || publickey || message)" - so that
// "every Red25519 signature is different, even when signing the same data with
// the same key" (https://geti2p.net/spec/encryptedleaseset §"Sign/Verify
// Calculations"). A sigType 11 outer signature is produced by
// github.com/go-i2p/crypto/red25519, whose Red25519Signer draws the 80-byte
// random T per message (see its TestRed25519SignaturesAreRandomized), so
// re-publications of the same lease set are not byte-correlatable. Verification
// uses the same package's cofactor/HStar VERIFY rule, not plain Ed25519's.
//
// A sigType 7 (Ed25519) outer signature is still accepted for the unblinded
// case the page describes ("The unblinded leaseset is signed by the unblinded
// Ed25519 or Red25519 signing private key ... as usual").
//
// To publish a blinded lease set, pass the blinded Red25519 scalar a' (from
// kdf.DeriveBlindingFactorI2P plus red25519.BlindPrivateKey in
// github.com/go-i2p/crypto) as the signing key with sigType 11; an Ed25519
// private key is converted with the spec's CONVERT_ED25519_PRIVATE.
//
// Blinding and signing arithmetic are provided by github.com/go-i2p/crypto
// (kdf.DeriveBlindingFactorI2P, red25519.BlindPrivateKey/BlindPublicKey,
// red25519.Red25519Signer); this package implements no cryptographic primitives.
//
// # Specification
//
//   - Common Structures — EncryptedLeaseSet: https://geti2p.net/spec/common-structures#encryptedleaseset
//   - Encrypted LeaseSet Specification: https://geti2p.net/spec/encryptedleaseset
//   - Proposal 123: https://geti2p.net/spec/proposals/123-new-netdb-entries
package encrypted_leaseset
