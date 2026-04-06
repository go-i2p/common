// Package destination implements the I2P Destination common data structure
package destination

import (
	"bytes"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// NewDestination creates a new Destination from KeysAndCert.
// This is the primary constructor for creating destinations programmatically.
// Returns an error if the provided KeysAndCert is invalid or uses prohibited key types.
func NewDestination(keysAndCert *keys_and_cert.KeysAndCert) (*Destination, error) {
	if keysAndCert == nil {
		return nil, oops.Errorf("KeysAndCert cannot be nil")
	}
	if err := keysAndCert.Validate(); err != nil {
		return nil, oops.Errorf("invalid KeysAndCert: %w", err)
	}
	if err := validateDestinationKeyTypes(keysAndCert); err != nil {
		return nil, err
	}

	return &Destination{
		KeysAndCert: keysAndCert,
	}, nil
}

// NewDestinationFromBytes creates a Destination by parsing bytes.
// Returns a pointer for consistency with NewDestination.
// Returns the parsed Destination, remaining bytes, and any errors encountered.
func NewDestinationFromBytes(data []byte) (*Destination, []byte, error) {
	dest, remainder, err := ReadDestination(data)
	if err != nil {
		return nil, remainder, err
	}
	return &dest, remainder, nil
}

// Validate checks if the Destination is properly initialized and uses permitted key types.
// Returns an error if the destination or its components are invalid, or if prohibited
// key types (MLKEM crypto, RSA/Ed25519ph signing) are present.
func (d *Destination) Validate() error {
	if d == nil {
		return oops.Errorf("destination is nil")
	}
	if d.KeysAndCert == nil {
		return oops.Errorf("destination KeysAndCert is nil")
	}
	if err := d.KeysAndCert.Validate(); err != nil {
		return err
	}
	return validateDestinationKeyTypes(d.KeysAndCert)
}

// IsValid returns true if the Destination is properly initialized.
// This is a convenience method that returns false instead of an error.
func (d *Destination) IsValid() bool {
	return d.Validate() == nil
}

// Hash returns the SHA-256 hash of the Destination's binary representation.
// The I2P network database is keyed by SHA256(Destination).
// Returns an error if the destination is not properly initialized.
func (d *Destination) Hash() ([32]byte, error) {
	if d == nil || d.KeysAndCert == nil {
		return [32]byte{}, oops.Errorf("destination is not initialized")
	}
	b, err := d.KeysAndCert.Bytes()
	if err != nil {
		return [32]byte{}, err
	}
	return types.SHA256(b), nil
}

// Equals returns true if two Destinations are logically identical.
// For ElGamal+DSA-SHA1 destinations, both are canonicalized to the
// NULL certificate form before comparison, so a KEY(0,0) encoded destination
// and a NULL cert encoded destination will correctly compare as equal.
// Returns false if either destination is nil or not properly initialized.
func (d *Destination) Equals(other *Destination) bool {
	if !areDestinationsComparable(d, other) {
		return false
	}
	return compareCanonicalBytes(d, other)
}

// areDestinationsComparable checks that both destinations are non-nil and have
// valid KeysAndCert fields required for comparison.
func areDestinationsComparable(d, other *Destination) bool {
	if d == nil || other == nil {
		return false
	}
	return d.KeysAndCert != nil && other.KeysAndCert != nil
}

// compareCanonicalBytes canonicalizes both destinations and compares their
// serialized byte representations.
func compareCanonicalBytes(d, other *Destination) bool {
	dCanon, err := CanonicalizeDestination(d)
	if err != nil {
		return false
	}
	otherCanon, err := CanonicalizeDestination(other)
	if err != nil {
		return false
	}
	dBytes, err := dCanon.KeysAndCert.Bytes()
	if err != nil {
		return false
	}
	otherBytes, err := otherCanon.KeysAndCert.Bytes()
	if err != nil {
		return false
	}
	return bytes.Equal(dBytes, otherBytes)
}

// validateDestinationKeyTypes checks that the KeysAndCert does not use
// key types prohibited for Destinations. Per the I2P spec (0.9.67):
//   - Crypto: MLKEM512_X25519 (5), MLKEM768_X25519 (6), MLKEM1024_X25519 (7)
//     are "for Leasesets only, not for RIs or Destinations."
//   - Signing: RSA_SHA256_2048 (4), RSA_SHA384_3072 (5), RSA_SHA512_4096 (6)
//     are "Offline only; never used in Key Certificates for Destinations."
//   - Signing: EdDSA_SHA512_Ed25519ph (8) is "Offline only; never used in
//     Key Certificates for Destinations."
func validateDestinationKeyTypes(kac *keys_and_cert.KeysAndCert) error {
	if kac == nil || kac.KeyCertificate == nil {
		return nil
	}
	if err := validateDestinationCryptoType(kac); err != nil {
		return err
	}
	return validateDestinationSigningType(kac)
}

// validateDestinationCryptoType rejects crypto types prohibited for Destinations
// and warns about reserved/TBD types.
//
// MLKEM types (5-7) are explicitly prohibited: "for Leasesets only, not for
// RIs or Destinations."
//
// ECDH-P256 (1), ECDH-P384 (2), ECDH-P521 (3) are listed as "Reserved, see
// proposal 145" in the I2P spec crypto public key types table. They are not
// prohibited for destinations, but their specification is not yet finalized.
// A warning is logged for these types to alert callers without breaking
// forward compatibility.
func validateDestinationCryptoType(kac *keys_and_cert.KeysAndCert) error {
	cryptoType := kac.KeyCertificate.PublicKeyType()
	switch cryptoType {
	case key_certificate.KEYCERT_CRYPTO_MLKEM512_X25519,
		key_certificate.KEYCERT_CRYPTO_MLKEM768_X25519,
		key_certificate.KEYCERT_CRYPTO_MLKEM1024_X25519:
		return oops.Errorf(
			"crypto type %d is not permitted for Destinations (LeaseSet only)",
			cryptoType,
		)
	case key_certificate.KEYCERT_CRYPTO_P256,
		key_certificate.KEYCERT_CRYPTO_P384,
		key_certificate.KEYCERT_CRYPTO_P521:
		log.WithFields(logger.Fields{"pkg": "destination", "func": "validateDestinationCryptoType", "crypto_type": cryptoType}).Warn(
			"ECDH crypto type is reserved (proposal 145) and not yet finalized in the I2P spec")
	}
	return nil
}

// validateDestinationSigningType rejects signing types prohibited for Destinations.
// RSA types (4-6) and Ed25519ph (8) are offline-only and never used in
// Key Certificates for Destinations per the I2P spec.
func validateDestinationSigningType(kac *keys_and_cert.KeysAndCert) error {
	signingType := kac.KeyCertificate.SigningPublicKeyType()
	switch signingType {
	case key_certificate.KEYCERT_SIGN_RSA2048,
		key_certificate.KEYCERT_SIGN_RSA3072,
		key_certificate.KEYCERT_SIGN_RSA4096:
		return oops.Errorf(
			"signing type %d (RSA) is not permitted for Destinations (offline only)",
			signingType,
		)
	case key_certificate.KEYCERT_SIGN_ED25519PH:
		return oops.Errorf(
			"signing type %d (Ed25519ph) is not permitted for Destinations (offline only)",
			signingType,
		)
	}
	return nil
}

// CanonicalizeDestination returns an equivalent Destination in canonical
// wire form. Per the I2P spec, ElGamal+DSA-SHA1 Destinations must use a
// NULL certificate (3 bytes) rather than a KEY(0,0) certificate (7 bytes).
// Using the non-canonical form produces a different SHA256 address hash.
//
// For all other key types the original Destination is returned unchanged.
// The caller is responsible for updating any cached hashes after
// canonicalization.
func CanonicalizeDestination(d *Destination) (*Destination, error) {
	if d == nil || d.KeysAndCert == nil {
		return nil, oops.Errorf("destination is nil or not initialized")
	}
	if !needsCanonicalization(d) {
		return d, nil
	}
	return buildCanonicalDestination(d)
}

// needsCanonicalization returns true if the destination uses ElGamal+DSA-SHA1
// key types and may need to be re-encoded with a NULL certificate.
func needsCanonicalization(d *Destination) bool {
	if d.KeysAndCert.KeyCertificate == nil {
		return false
	}
	sigType := d.KeysAndCert.KeyCertificate.SigningPublicKeyType()
	cryptoType := d.KeysAndCert.KeyCertificate.PublicKeyType()
	return sigType == key_certificate.KEYCERT_SIGN_DSA_SHA1 &&
		cryptoType == key_certificate.KEYCERT_CRYPTO_ELG
}

// buildCanonicalDestination constructs an ElGamal+DSA-SHA1 destination with a
// 3-byte NULL certificate, replacing any KEY(0,0) certificate.
func buildCanonicalDestination(d *Destination) (*Destination, error) {
	b, err := d.KeysAndCert.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize destination for canonicalization: %w", err)
	}
	if len(b) < keys_and_cert.KEYS_AND_CERT_DATA_SIZE {
		return nil, oops.Errorf("destination bytes too short for canonicalization: %d < %d",
			len(b), keys_and_cert.KEYS_AND_CERT_DATA_SIZE)
	}
	canonical := make([]byte, keys_and_cert.KEYS_AND_CERT_DATA_SIZE+3)
	copy(canonical, b[:keys_and_cert.KEYS_AND_CERT_DATA_SIZE])
	canonical[keys_and_cert.KEYS_AND_CERT_DATA_SIZE] = 0x00   // cert type = NULL
	canonical[keys_and_cert.KEYS_AND_CERT_DATA_SIZE+1] = 0x00 // length high byte
	canonical[keys_and_cert.KEYS_AND_CERT_DATA_SIZE+2] = 0x00 // length low byte
	dest, _, readErr := readDestinationRaw(canonical)
	if readErr != nil {
		return nil, oops.Errorf("failed to parse canonical destination: %w", readErr)
	}
	return &dest, nil
}

// NewDestinationWithCompressiblePadding creates a new Destination and
// auto-generates Proposal 161-compliant compressible padding from the key
// certificate and key sizes. This is the recommended constructor for new
// Destinations per I2P spec 0.9.57+.
//
// Each 32-byte padding block is derived deterministically from a single
// random seed, allowing SSU2/I2NP Database Store messages to compress
// the padding efficiently.
//
// Returns an error if the certificate specifies unknown key types (where
// CryptoPublicKeySize or SigningPublicKeySizeOrError return 0/error),
// or if the certificate is not a valid KEY certificate.
func NewDestinationWithCompressiblePadding(
	publicKey types.ReceivingPublicKey,
	signingPublicKey types.SigningPublicKey,
	cert *certificate.Certificate,
) (*Destination, error) {
	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	if err != nil {
		return nil, oops.Errorf("failed to create KeyCertificate from certificate: %w", err)
	}
	padding, err := generatePaddingFromCert(keyCert)
	if err != nil {
		return nil, err
	}
	kac, err := keys_and_cert.NewKeysAndCert(keyCert, publicKey, padding, signingPublicKey)
	if err != nil {
		return nil, err
	}
	return NewDestination(kac)
}

// generatePaddingFromCert calculates the required padding size from key
// certificate sizes and generates Proposal 161-compliant compressible padding.
func generatePaddingFromCert(keyCert *key_certificate.KeyCertificate) ([]byte, error) {
	cryptoSize, err := keyCert.CryptoPublicKeySize()
	if err != nil {
		return nil, oops.Errorf("unknown crypto key type for padding calculation: %w", err)
	}
	sigSize, err := keyCert.SigningPublicKeySizeOrError()
	if err != nil {
		return nil, oops.Errorf("unknown signing key type for padding calculation: %w", err)
	}
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - cryptoSize - sigSize
	if paddingSize < 0 {
		paddingSize = 0
	}
	return keys_and_cert.GenerateCompressiblePadding(paddingSize)
}
