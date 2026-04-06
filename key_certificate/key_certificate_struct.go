// Package key_certificate implements the I2P KeyCertificate common data structure
package key_certificate

import (
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/dsa"
	"github.com/go-i2p/crypto/ecdsa"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/ed25519ph"
	elgamal "github.com/go-i2p/crypto/elg"
	i2prsa "github.com/go-i2p/crypto/rsa"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
)

// KeyCertificate represents an I2P Key Certificate structure
// https://geti2p.net/spec/common-structures#certificate
// Accurate for version 0.9.67
//
// +----+----+----+----+----+-//
// |type| length  | payload
// +----+----+----+----+----+-//
//
// type :: Integer
//
//	length -> 1 byte
//
//	case 0 -> NULL
//	case 1 -> HASHCASH
//	case 2 -> HIDDEN
//	case 3 -> SIGNED
//	case 4 -> MULTIPLE
//	case 5 -> KEY
//
// length :: Integer
//
//	length -> 2 bytes
//
// payload :: data
//
//	length -> $length bytes
type KeyCertificate struct {
	certificate.Certificate
	SpkType data.Integer
	CpkType data.Integer
}

// NewKeyCertificate creates a new *KeyCertificate from []byte using ReadCertificate.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func NewKeyCertificate(bytes []byte) (key_certificate *KeyCertificate, remainder []byte, err error) {
	log.WithFields(logger.Fields{
		"pkg":          "key_certificate",
		"func":         "NewKeyCertificate",
		"input_length": len(bytes),
	}).Debug("Creating new keyCertificate")

	cert, remainder, err := parseBaseCertificate(bytes)
	if err != nil {
		return nil, remainder, err
	}

	if err = validateKeyCertificateType(cert); err != nil {
		return nil, remainder, err
	}

	certData, err := cert.Data()
	if err != nil {
		return nil, remainder, err
	}

	if err = validateKeyCertificateDataLength(certData); err != nil {
		return nil, remainder, err
	}

	spkType, cpkType := extractKeyTypes(certData)

	if validationErr := validatePayloadLengthAgainstKeyTypes(certData, spkType, cpkType); validationErr != nil {
		log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "NewKeyCertificate"}).WithError(validationErr).Error("Key certificate payload length mismatch")
		return nil, remainder, validationErr
	}

	key_certificate = buildKeyCertificate(cert, spkType, cpkType)

	return key_certificate, remainder, err
}

// parseBaseCertificate reads and validates the base certificate structure.
// Returns the parsed certificate, remaining bytes, and any error encountered.
func parseBaseCertificate(bytes []byte) (*certificate.Certificate, []byte, error) {
	cert, remainder, err := certificate.ReadCertificate(bytes)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "parseBaseCertificate"}).WithError(err).Error("Failed to read Certificate")
		return cert, remainder, err
	}
	return cert, remainder, nil
}

// validateKeyCertificateType validates that the certificate is specifically a Key Certificate type.
// Only CERT_KEY type certificates can be converted to KeyCertificate structures.
func validateKeyCertificateType(cert *certificate.Certificate) error {
	kind, err := cert.Type()
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "validateKeyCertificateType", "reason": "invalid certificate type"}).Error(err.Error())
		return err
	}
	if kind != certificate.CERT_KEY {
		return oops.Errorf("invalid certificate type: %d", kind)
	}
	return nil
}

// validateKeyCertificateDataLength ensures the certificate payload contains sufficient data for key type fields.
// Key certificates require at least 4 bytes: 2 for signing key type, 2 for crypto key type.
func validateKeyCertificateDataLength(certData []byte) error {
	if len(certData) < 4 {
		return oops.Errorf("key certificate data too short")
	}
	log.WithFields(logger.Fields{
		"pkg":            "key_certificate",
		"func":           "validateKeyCertificateDataLength",
		"spk_type_bytes": certData[0:2],
		"cpk_type_bytes": certData[2:4],
	}).Debug("Certificate data in NewKeyCertificate")
	return nil
}

// validatePayloadLengthAgainstKeyTypes checks that the key certificate payload length
// matches the expected excess key data for the declared signing and crypto key types.
// Per spec: excess key data is appended when key sizes exceed the standard field sizes.
func validatePayloadLengthAgainstKeyTypes(certData []byte, spkType, cpkType data.Integer) error {
	sigType := spkType.Int()
	crypType := cpkType.Int()

	sigInfo, sigExists := SigningKeySizes[sigType]
	crypInfo, crypExists := CryptoKeySizes[crypType]
	if !sigExists || !crypExists {
		// Unknown types bypass size validation — we can't know the expected payload.
		// Log a warning since this may indicate a forward-compatibility gap where
		// the spec's "prohibit excess data" rule is not enforced.
		log.WithFields(logger.Fields{
			"pkg":            "key_certificate",
			"func":           "validatePayloadLengthAgainstKeyTypes",
			"signing_type":   sigType,
			"signing_known":  sigExists,
			"crypto_type":    crypType,
			"crypto_known":   crypExists,
			"payload_length": len(certData),
		}).Warn("Skipping payload length validation for unknown key type(s)")
		return nil
	}

	excessSigning := 0
	if sigInfo.SigningPublicKeySize > KEYCERT_SPK_SIZE {
		excessSigning = sigInfo.SigningPublicKeySize - KEYCERT_SPK_SIZE
	}
	excessCrypto := 0
	if crypInfo.CryptoPublicKeySize > KEYCERT_PUBKEY_SIZE {
		excessCrypto = crypInfo.CryptoPublicKeySize - KEYCERT_PUBKEY_SIZE
	}

	expectedLen := 4 + excessSigning + excessCrypto
	if len(certData) < expectedLen {
		return oops.Errorf("key certificate payload too short: need %d bytes for types (sig=%d, crypto=%d), got %d",
			expectedLen, sigType, crypType, len(certData))
	}
	// Per I2P spec: "implementers are cautioned to prohibit excess data in Certificates"
	if len(certData) > expectedLen {
		return oops.Errorf("key certificate payload too long: expected %d bytes for types (sig=%d, crypto=%d), got %d",
			expectedLen, sigType, crypType, len(certData))
	}
	return nil
}

// extractKeyTypes extracts the signing public key type and crypto public key type from certificate data.
// Returns the signing key type and crypto key type as I2P Integers.
func extractKeyTypes(certData []byte) (data.Integer, data.Integer) {
	spkType, _ := data.ReadInteger(certData[0:2], 2)
	cpkType, _ := data.ReadInteger(certData[2:4], 2)
	log.WithFields(logger.Fields{
		"pkg":      "key_certificate",
		"func":     "extractKeyTypes",
		"cpk_type": cpkType.Int(),
		"spk_type": spkType.Int(),
	}).Debug("Extracted key types in NewKeyCertificate")
	return spkType, cpkType
}

// buildKeyCertificate constructs a KeyCertificate from the parsed components.
// Returns a fully initialized KeyCertificate with logging of the created key types.
func buildKeyCertificate(cert *certificate.Certificate, spkType, cpkType data.Integer) *KeyCertificate {
	key_certificate := &KeyCertificate{
		Certificate: *cert,
		CpkType:     cpkType,
		SpkType:     spkType,
	}
	log.WithFields(logger.Fields{
		"pkg":      "key_certificate",
		"func":     "buildKeyCertificate",
		"spk_type": key_certificate.SpkType.Int(),
		"cpk_type": key_certificate.CpkType.Int(),
	}).Debug("Successfully created new keyCertificate")
	return key_certificate
}

// KeyCertificateFromCertificate creates a KeyCertificate from an existing Certificate
func KeyCertificateFromCertificate(cert *certificate.Certificate) (*KeyCertificate, error) {
	if err := validateKeyCertificateType(cert); err != nil {
		return nil, err
	}

	certData, err := cert.Data()
	if err != nil {
		return nil, err
	}

	if err := validateKeyCertificateDataLength(certData); err != nil {
		return nil, err
	}

	spkType, cpkType := extractKeyTypes(certData)
	logExtractedKeyTypes(certData, spkType, cpkType)

	if validationErr := validatePayloadLengthAgainstKeyTypes(certData, spkType, cpkType); validationErr != nil {
		log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "KeyCertificateFromCertificate"}).WithError(validationErr).Error("Key certificate payload length mismatch in KeyCertificateFromCertificate")
		return nil, validationErr
	}

	keyCert := buildKeyCertificate(cert, spkType, cpkType)
	return keyCert, nil
}

// logExtractedKeyTypes logs detailed debug information about extracted key types.
func logExtractedKeyTypes(certData []byte, spkType, cpkType data.Integer) {
	log.WithFields(logger.Fields{
		"pkg":          "key_certificate",
		"func":         "logExtractedKeyTypes",
		"data_length":  len(certData),
		"spk_type_int": spkType.Int(),
		"cpk_type_int": cpkType.Int(),
	}).Debug("Extracted key types from certificate data")
}

// Data returns the certificate payload bytes (the key type fields and any excess key data),
// NOT the full serialized certificate. For the full certificate bytes (type+length+payload),
// use Certificate.RawBytes() instead.
func (keyCertificate KeyCertificate) Data() ([]byte, error) {
	data, err := keyCertificate.Certificate.Data()
	if err != nil {
		return nil, err
	}
	log.WithFields(logger.Fields{
		"pkg":         "key_certificate",
		"func":        "KeyCertificate.Data",
		"data_length": len(data),
	}).Debug("Retrieved payload data from keyCertificate")
	return data, nil
}

// SigningPublicKeyType returns the signingPublicKey type as a Go integer.
func (keyCertificate KeyCertificate) SigningPublicKeyType() (signing_pubkey_type int) {
	signing_pubkey_type = keyCertificate.SpkType.Int()
	log.WithFields(logger.Fields{
		"pkg":                 "key_certificate",
		"func":                "KeyCertificate.SigningPublicKeyType",
		"signing_pubkey_type": signing_pubkey_type,
	}).Debug("Retrieved signingPublicKey type")
	return keyCertificate.SpkType.Int()
}

// PublicKeyType returns the publicKey type as a Go integer.
func (keyCertificate KeyCertificate) PublicKeyType() (pubkey_type int) {
	pubkey_type = keyCertificate.CpkType.Int()
	log.WithFields(logger.Fields{
		"pkg":         "key_certificate",
		"func":        "KeyCertificate.PublicKeyType",
		"pubkey_type": pubkey_type,
	}).Debug("Retrieved publicKey type")
	return keyCertificate.CpkType.Int()
}

// ConstructPublicKey returns a publicKey constructed using any excess data that may be stored in the KeyCertificate.
// The data parameter must be the full 256-byte public key field from the KeysAndCert structure.
// Per the I2P spec, the crypto public key is start-aligned (bytes 0..keySize-1) within the field.
// Returns any errors encountered while parsing.
func (keyCertificate KeyCertificate) ConstructPublicKey(data []byte) (public_key types.ReceivingPublicKey, err error) {
	log.WithFields(logger.Fields{
		"pkg":          "key_certificate",
		"func":         "KeyCertificate.ConstructPublicKey",
		"input_length": len(data),
	}).Debug("Constructing publicKey from keyCertificate")
	if err = validatePublicKeyDataLength(data); err != nil {
		return public_key, err
	}
	key_type := keyCertificate.PublicKeyType()
	return constructPublicKeyByType(key_type, data)
}

// validatePublicKeyDataLength checks that the input data is at least as large
// as the full 256-byte public key field from KeysAndCert.
func validatePublicKeyDataLength(data []byte) error {
	if len(data) < KEYCERT_PUBKEY_SIZE {
		log.WithFields(logger.Fields{
			"pkg":          "key_certificate",
			"func":         "validatePublicKeyDataLength",
			"at":           "(keyCertificate) ConstructPublicKey",
			"data_len":     len(data),
			"required_len": KEYCERT_PUBKEY_SIZE,
			"reason":       "not enough data",
		}).Error("error constructing public key")
		return oops.Errorf("error constructing public key: not enough data")
	}
	return nil
}

// constructPublicKeyByType dispatches public key construction to the appropriate
// handler based on the crypto key type code.
func constructPublicKeyByType(key_type int, data []byte) (types.ReceivingPublicKey, error) {
	switch key_type {
	case KEYCERT_CRYPTO_ELG:
		return constructElGamalKey(data), nil
	case KEYCERT_CRYPTO_P256:
		return constructECDHKey(data, newECDHP256PublicKey, "ECDH-P256")
	case KEYCERT_CRYPTO_P384:
		return constructECDHKey(data, newECDHP384PublicKey, "ECDH-P384")
	case KEYCERT_CRYPTO_P521:
		return constructECDHKey(data, newECDHP521PublicKey, "ECDH-P521")
	case KEYCERT_CRYPTO_X25519,
		KEYCERT_CRYPTO_MLKEM512_X25519,
		KEYCERT_CRYPTO_MLKEM768_X25519,
		KEYCERT_CRYPTO_MLKEM1024_X25519:
		return constructCurve25519Key(data), nil
	case KEYCERT_CRYPTO_RESERVED_NONE:
		log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructPublicKeyByType"}).Warn("Crypto key type 255 (RESERVED_NONE) is reserved by spec and not implemented")
		return nil, oops.Errorf("reserved crypto key type: RESERVED_NONE (type %d)", KEYCERT_CRYPTO_RESERVED_NONE)
	default:
		log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructPublicKeyByType", "key_type": key_type}).Warn("Unknown public key type")
		return nil, oops.Errorf("unknown crypto key type: %d", key_type)
	}
}

// constructElGamalKey builds an ElGamal public key from the 256-byte field.
func constructElGamalKey(data []byte) elgamal.ElgPublicKey {
	var elg_key elgamal.ElgPublicKey
	copy(elg_key[:], data[0:KEYCERT_CRYPTO_ELG_SIZE])
	log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructElGamalKey"}).Debug("Constructed ElgPublicKey")
	return elg_key
}

// constructECDHKey builds an ECDH public key using the provided constructor
// function and logs the result.
func constructECDHKey(data []byte, constructor func([]byte) (types.ReceivingPublicKey, error), name string) (types.ReceivingPublicKey, error) {
	key, err := constructor(data)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructECDHKey"}).WithError(err).Warn("Failed to construct " + name + " public key")
	} else {
		log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructECDHKey"}).Debug("Constructed " + name + " public key")
	}
	return key, err
}

// constructCurve25519Key builds a Curve25519 public key from the 256-byte field.
func constructCurve25519Key(data []byte) curve25519.Curve25519PublicKey {
	curve25519_key := make(curve25519.Curve25519PublicKey, KEYCERT_CRYPTO_X25519_SIZE)
	copy(curve25519_key, data[0:KEYCERT_CRYPTO_X25519_SIZE])
	log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructCurve25519Key"}).Debug("Constructed Curve25519PublicKey")
	return curve25519_key
}

// CryptoPublicKeySize returns the size of a public key for the certificate's crypto type
func (keyCertificate KeyCertificate) CryptoPublicKeySize() (int, error) {
	info, exists := CryptoKeySizes[keyCertificate.CpkType.Int()]
	if !exists {
		return 0, oops.Errorf("unknown crypto key type: %d", keyCertificate.CpkType.Int())
	}
	return info.CryptoPublicKeySize, nil
}

// SigningPublicKeySize returns the size of a signing public key for the certificate's signing type.
// Returns 0 for unknown signing types – callers must treat 0 as an error condition because no
// valid signing key has size 0.  For an error-returning variant use SigningPublicKeySizeOrError.
func (keyCertificate KeyCertificate) SigningPublicKeySize() int {
	spkType := keyCertificate.SpkType.Int()
	info, exists := SigningKeySizes[spkType]
	if !exists {
		log.WithFields(logger.Fields{
			"pkg":              "key_certificate",
			"func":             "KeyCertificate.SigningPublicKeySize",
			"signing_key_type": spkType,
		}).Warn("Unknown signing key type for size lookup, returning 0")
		return 0
	}
	return info.SigningPublicKeySize
}

// SigningPublicKeySizeOrError returns the size of a signing public key for the certificate's
// signing type, or an error if the type is unknown.  Prefer this over SigningPublicKeySize
// when callers need to distinguish "unknown type" from a hypothetical 0-byte key.
func (keyCertificate KeyCertificate) SigningPublicKeySizeOrError() (int, error) {
	spkType := keyCertificate.SpkType.Int()
	info, exists := SigningKeySizes[spkType]
	if !exists {
		return 0, oops.Errorf("unknown signing key type: %d", spkType)
	}
	return info.SigningPublicKeySize, nil
}

// validateSigningKeyData validates that sufficient data is available for signing key construction.
// Returns an error if the data length is insufficient for the required signature size.
func validateSigningKeyData(dataLen, requiredSize int) error {
	if dataLen < requiredSize {
		log.WithFields(logger.Fields{
			"pkg":          "key_certificate",
			"func":         "validateSigningKeyData",
			"at":           "validateSigningKeyData",
			"data_len":     dataLen,
			"required_len": requiredSize,
			"reason":       "not enough data",
		}).Error("error constructing signing public key")
		return oops.Errorf("error constructing signing public key: not enough data")
	}
	return nil
}

// constructDSAKey constructs a DSA-SHA1 signing public key from certificate data.
// Legacy DSA-SHA1 signing key construction for backwards compatibility.
//
// DSA fills the entire 128-byte SPK field (KEYCERT_SIGN_DSA_SHA1_SIZE == KEYCERT_SPK_SIZE).
func constructDSAKey(data []byte) (types.SigningPublicKey, error) {
	if len(data) < KEYCERT_SIGN_DSA_SHA1_SIZE {
		return nil, oops.Errorf("insufficient data for DSA key: expected at least %d bytes, got %d",
			KEYCERT_SIGN_DSA_SHA1_SIZE, len(data))
	}
	var dsa_key dsa.DSAPublicKey
	// DSA key size == SPK field size (128 bytes), so the key fills the entire field.
	// Use end-alignment for consistency: data[SPK_SIZE-DSA_SIZE : SPK_SIZE] == data[0:128].
	copy(dsa_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_DSA_SHA1_SIZE:KEYCERT_SPK_SIZE])
	log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructDSAKey"}).Debug("Constructed DSAPublicKey")
	return dsa_key, nil
}

// constructECDSAP256Key constructs an ECDSA P-256 signing public key from certificate data.
// Provides 128-bit security level with compact 64-byte keys.
// Accepts either padded data (128 bytes, key at end) or raw key data (64 bytes).
func constructECDSAP256Key(data []byte) (types.SigningPublicKey, error) {
	if len(data) < KEYCERT_SIGN_P256_SIZE {
		return nil, oops.Errorf("insufficient data for P256 key: expected at least %d bytes, got %d",
			KEYCERT_SIGN_P256_SIZE, len(data))
	}
	var ec_p256_key ecdsa.ECP256PublicKey
	if len(data) >= KEYCERT_SPK_SIZE {
		// Padded format: extract key from the end of the 128-byte field
		copy(ec_p256_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_P256_SIZE:KEYCERT_SPK_SIZE])
	} else {
		// Raw key data
		copy(ec_p256_key[:], data[:KEYCERT_SIGN_P256_SIZE])
	}
	log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructECDSAP256Key"}).Debug("Constructed P256PublicKey")
	return ec_p256_key, nil
}

// constructECDSAP384Key constructs an ECDSA P-384 signing public key from certificate data.
// Provides 192-bit security level with 96-byte keys.
// Accepts either padded data (128 bytes, key at end) or raw key data (96 bytes).
func constructECDSAP384Key(data []byte) (types.SigningPublicKey, error) {
	if len(data) < KEYCERT_SIGN_P384_SIZE {
		return nil, oops.Errorf("insufficient data for P384 key: expected at least %d bytes, got %d",
			KEYCERT_SIGN_P384_SIZE, len(data))
	}
	var ec_p384_key ecdsa.ECP384PublicKey
	if len(data) >= KEYCERT_SPK_SIZE {
		// Padded format: extract key from the end of the 128-byte field
		copy(ec_p384_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_P384_SIZE:KEYCERT_SPK_SIZE])
	} else {
		// Raw key data
		copy(ec_p384_key[:], data[:KEYCERT_SIGN_P384_SIZE])
	}
	log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructECDSAP384Key"}).Debug("Constructed P384PublicKey")
	return ec_p384_key, nil
}

// constructECDSAP521Key constructs an ECDSA P-521 signing public key from certificate data.
// Provides 256-bit security level with 132-byte keys.
// P521 keys (132 bytes) exceed KEYCERT_SPK_SIZE (128 bytes), so the key certificate
// payload contains 4 bytes of excess signing key data that must be concatenated
// with the 128-byte inline SPK field from KeysAndCert.
// Accepts either full-field data (132+ bytes with excess prepended) or raw key data (132 bytes).
func constructECDSAP521Key(data []byte) (types.SigningPublicKey, error) {
	if len(data) < KEYCERT_SIGN_P521_SIZE {
		return nil, oops.Errorf("insufficient data for P521 key: expected at least %d bytes, got %d",
			KEYCERT_SIGN_P521_SIZE, len(data))
	}
	var ec_p521_key ecdsa.ECP521PublicKey
	copy(ec_p521_key[:], data[:KEYCERT_SIGN_P521_SIZE])
	log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructECDSAP521Key"}).Debug("Constructed P521PublicKey")
	return ec_p521_key, nil
}

// constructRSA2048Key constructs an RSA-2048 signing public key from certificate data.
// RSA-2048 keys (256 bytes) exceed KEYCERT_SPK_SIZE (128 bytes), requiring 128 bytes
// of excess signing key data from the key certificate payload.
func constructRSA2048Key(data []byte) (types.SigningPublicKey, error) {
	if len(data) < KEYCERT_SIGN_RSA2048_SIZE {
		return nil, oops.Errorf("insufficient data for RSA2048 key: expected at least %d bytes, got %d",
			KEYCERT_SIGN_RSA2048_SIZE, len(data))
	}
	key, err := i2prsa.NewRSA2048PublicKey(data[:KEYCERT_SIGN_RSA2048_SIZE])
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct RSA2048 public key")
	}
	log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructRSA2048Key"}).Debug("Constructed RSA2048PublicKey")
	return *key, nil
}

// constructRSA3072Key constructs an RSA-3072 signing public key from certificate data.
// RSA-3072 keys (384 bytes) exceed KEYCERT_SPK_SIZE (128 bytes), requiring 256 bytes
// of excess signing key data from the key certificate payload.
func constructRSA3072Key(data []byte) (types.SigningPublicKey, error) {
	if len(data) < KEYCERT_SIGN_RSA3072_SIZE {
		return nil, oops.Errorf("insufficient data for RSA3072 key: expected at least %d bytes, got %d",
			KEYCERT_SIGN_RSA3072_SIZE, len(data))
	}
	key, err := i2prsa.NewRSA3072PublicKey(data[:KEYCERT_SIGN_RSA3072_SIZE])
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct RSA3072 public key")
	}
	log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructRSA3072Key"}).Debug("Constructed RSA3072PublicKey")
	return *key, nil
}

// constructRSA4096Key constructs an RSA-4096 signing public key from certificate data.
// RSA-4096 keys (512 bytes) exceed KEYCERT_SPK_SIZE (128 bytes), requiring 384 bytes
// of excess signing key data from the key certificate payload.
func constructRSA4096Key(data []byte) (types.SigningPublicKey, error) {
	if len(data) < KEYCERT_SIGN_RSA4096_SIZE {
		return nil, oops.Errorf("insufficient data for RSA4096 key: expected at least %d bytes, got %d",
			KEYCERT_SIGN_RSA4096_SIZE, len(data))
	}
	key, err := i2prsa.NewRSA4096PublicKey(data[:KEYCERT_SIGN_RSA4096_SIZE])
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct RSA4096 public key")
	}
	log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructRSA4096Key"}).Debug("Constructed RSA4096PublicKey")
	return *key, nil
}

// constructEd25519Key constructs an Ed25519 signing public key from certificate data.
// Ed25519 provides excellent security with 32-byte keys and fast verification.
// Accepts either padded data (128 bytes, key at end) or raw key data (32 bytes exact),
// consistent with the ECDSA key constructors.
func constructEd25519Key(data []byte) (types.SigningPublicKey, error) {
	if len(data) < KEYCERT_SIGN_ED25519_SIZE {
		return nil, oops.Errorf("insufficient data for Ed25519 key: expected at least %d bytes, got %d",
			KEYCERT_SIGN_ED25519_SIZE, len(data))
	}

	var keyBytes []byte
	if len(data) >= KEYCERT_SPK_SIZE {
		// Padded format: extract key from the end of the 128-byte field
		keyBytes = data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_ED25519_SIZE : KEYCERT_SPK_SIZE]
	} else {
		// Raw key data (exactly 32 bytes)
		keyBytes = data[:KEYCERT_SIGN_ED25519_SIZE]
	}

	ed25519_key, err := ed25519.NewEd25519PublicKey(keyBytes)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct Ed25519 public key")
	}
	log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructEd25519Key"}).Debug("Constructed Ed25519PublicKey")
	return ed25519_key, nil
}

// constructEd25519PHKey constructs an Ed25519ph (pre-hashed) signing public key from certificate data.
// Uses the same key format as Ed25519 but with pre-hashing for efficiency.
// Accepts either padded data (128 bytes, key at end) or raw key data (32 bytes exact),
// consistent with the ECDSA key constructors.
func constructEd25519PHKey(data []byte) (types.SigningPublicKey, error) {
	if len(data) < KEYCERT_SIGN_ED25519PH_SIZE {
		return nil, oops.Errorf("insufficient data for Ed25519ph key: expected at least %d bytes, got %d",
			KEYCERT_SIGN_ED25519PH_SIZE, len(data))
	}

	var keyBytes []byte
	if len(data) >= KEYCERT_SPK_SIZE {
		// Padded format: extract key from the end of the 128-byte field
		keyBytes = data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_ED25519PH_SIZE : KEYCERT_SPK_SIZE]
	} else {
		// Raw key data (exactly 32 bytes)
		keyBytes = data[:KEYCERT_SIGN_ED25519PH_SIZE]
	}

	ed25519ph_key, err := ed25519ph.NewEd25519phPublicKey(keyBytes)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct Ed25519ph public key")
	}
	log.WithFields(logger.Fields{"pkg": "key_certificate", "func": "constructEd25519PHKey"}).Debug("Constructed Ed25519PHPublicKey")
	return ed25519ph_key, nil
}

// constructRedDSAKey constructs a RedDSA (randomized EdDSA) signing public key.
// Per the I2P spec (0.9.39+), RedDSA-Ed25519 uses the same 32-byte Ed25519 curve
// point format for public keys. This wrapper delegates to constructEd25519Key and
// exists to decouple from any future divergence in the RedDSA key format.
func constructRedDSAKey(data []byte) (types.SigningPublicKey, error) {
	return constructEd25519Key(data)
}

// ConstructSigningPublicKey returns a SigningPublicKey constructed using any excess data that may be stored in the KeyCertificate.
// Returns any errors encountered while parsing.
//
// The data parameter must be the combined byte slice used to reconstruct the signing key:
//   - For types where the signing key fits within KEYCERT_SPK_SIZE (128 bytes) – e.g. Ed25519,
//     DSA, P256, P384 – data is the full 128-byte SPK field from the KeysAndCert structure.
//   - For types whose signing key exceeds KEYCERT_SPK_SIZE – P521 (132 bytes), RSA-2048 (256 bytes),
//     RSA-3072 (384 bytes), RSA-4096 (512 bytes) – the caller MUST pre-concatenate the
//     excess bytes from the key certificate payload (stored immediately after the 4-byte
//     type fields) FOLLOWED BY the 128-byte inline SPK field from KeysAndCert.
//     Per the I2P spec, signing keys are end-aligned in the SPK field: the inline
//     128 bytes contain the LAST 128 bytes of the key, while the excess bytes in
//     the certificate payload contain the FIRST (keySize − 128) bytes.
//     Correct order: excess || inline.  Failure to include the excess bytes or
//     using the wrong order will result in a truncated / incorrect key.
func (keyCertificate KeyCertificate) ConstructSigningPublicKey(data []byte) (signing_public_key types.SigningPublicKey, err error) {
	log.WithFields(logger.Fields{
		"pkg":          "key_certificate",
		"func":         "KeyCertificate.ConstructSigningPublicKey",
		"input_length": len(data),
	}).Debug("Constructing signingPublicKey from keyCertificate")

	signing_key_type := keyCertificate.SigningPublicKeyType()
	logSigningKeyDebug(signing_key_type, len(data))

	if err = validateSigningKeyData(len(data), keyCertificate.SigningPublicKeySize()); err != nil {
		return signing_public_key, err
	}

	signing_public_key, err = selectSigningKeyConstructor(signing_key_type, data)
	return signing_public_key, err
}

// logSigningKeyDebug logs debug information about the signing key construction.
func logSigningKeyDebug(signing_key_type, data_len int) {
	log.WithFields(logger.Fields{
		"pkg":              "key_certificate",
		"func":             "logSigningKeyDebug",
		"signing_key_type": signing_key_type,
		"data_len":         data_len,
		"required_len":     KEYCERT_SPK_SIZE,
	}).Debug("DEBUG: About to construct signing public key")
}

// selectSigningKeyConstructor selects and invokes the appropriate key constructor based on signing key type.
// Returns the constructed signing public key or an error if the key type is unknown or unimplemented.
func selectSigningKeyConstructor(signing_key_type int, data []byte) (types.SigningPublicKey, error) {
	switch signing_key_type {
	case KEYCERT_SIGN_DSA_SHA1:
		return constructDSAKey(data)
	case KEYCERT_SIGN_P256:
		return constructECDSAP256Key(data)
	case KEYCERT_SIGN_P384:
		return constructECDSAP384Key(data)
	case KEYCERT_SIGN_P521:
		return constructECDSAP521Key(data)
	case KEYCERT_SIGN_RSA2048:
		return constructRSA2048Key(data)
	case KEYCERT_SIGN_RSA3072:
		return constructRSA3072Key(data)
	case KEYCERT_SIGN_RSA4096:
		return constructRSA4096Key(data)
	case KEYCERT_SIGN_ED25519:
		return constructEd25519Key(data)
	case KEYCERT_SIGN_ED25519PH:
		return constructEd25519PHKey(data)
	case KEYCERT_SIGN_REDDSA_ED25519:
		return constructRedDSAKey(data)
	default:
		log.WithFields(logger.Fields{
			"pkg":              "key_certificate",
			"func":             "selectSigningKeyConstructor",
			"signing_key_type": signing_key_type,
		}).Warn("Unknown signing key type")
		return nil, oops.Errorf("unknown signing key type: %d", signing_key_type)
	}
}

// SignatureSize return the size of a Signature corresponding to the Key Certificate's signingPublicKey type.
// This returns the actual signature size (not the signing public key size).
// For signing public key sizes, use SigningPublicKeySize().
// Returns 0 for unknown signing types – callers must treat 0 as an error condition.
func (keyCertificate KeyCertificate) SignatureSize() (size int) {
	key_type := keyCertificate.SigningPublicKeyType()
	// Use the authoritative SigningKeySizes map which has correct signature sizes
	info, exists := SigningKeySizes[key_type]
	if !exists {
		log.WithFields(logger.Fields{
			"pkg":      "key_certificate",
			"func":     "KeyCertificate.SignatureSize",
			"key_type": key_type,
		}).Warn("Unknown signing key type for signature size lookup")
		return 0
	}
	log.WithFields(logger.Fields{
		"pkg":            "key_certificate",
		"func":           "KeyCertificate.SignatureSize",
		"key_type":       key_type,
		"signature_size": info.SignatureSize,
	}).Debug("Retrieved signature size")
	return info.SignatureSize
}

// SignatureSizeOrError returns the signature size for the certificate's signing key type,
// or an error if the type is unknown. Prefer this over SignatureSize when callers need
// to distinguish \"unknown type\" from a hypothetical 0-byte signature.
func (keyCertificate KeyCertificate) SignatureSizeOrError() (int, error) {
	key_type := keyCertificate.SigningPublicKeyType()
	info, exists := SigningKeySizes[key_type]
	if !exists {
		return 0, oops.Errorf("unknown signing key type: %d", key_type)
	}
	return info.SignatureSize, nil
}

// CryptoSize return the size of a Public Key corresponding to the Key Certificate's publicKey type.
func (keyCertificate KeyCertificate) CryptoSize() (size int) {
	key_type := keyCertificate.PublicKeyType()
	// Use the authoritative CryptoKeySizes map which includes all spec-defined types
	info, exists := CryptoKeySizes[key_type]
	if !exists {
		log.WithFields(logger.Fields{
			"pkg":      "key_certificate",
			"func":     "KeyCertificate.CryptoSize",
			"key_type": key_type,
		}).Warn("Unknown crypto key type for size lookup")
		return 0
	}
	log.WithFields(logger.Fields{
		"pkg":         "key_certificate",
		"func":        "KeyCertificate.CryptoSize",
		"key_type":    key_type,
		"crypto_size": info.CryptoPublicKeySize,
	}).Debug("Retrieved crypto size")
	return info.CryptoPublicKeySize
}

// CryptoSizeOrError returns the crypto public key size for the certificate's public key type,
// or an error if the type is unknown. Prefer this over CryptoSize when callers need
// to distinguish "unknown type" from a hypothetical 0-byte key.
func (keyCertificate KeyCertificate) CryptoSizeOrError() (int, error) {
	key_type := keyCertificate.PublicKeyType()
	info, exists := CryptoKeySizes[key_type]
	if !exists {
		return 0, oops.Errorf("unknown crypto key type: %d", key_type)
	}
	return info.CryptoPublicKeySize, nil
}
