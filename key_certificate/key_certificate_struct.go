// Package key_certificate implements the I2P Destination common data structure
package key_certificate

import (
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/dsa"
	"github.com/go-i2p/crypto/ecdsa"
	"github.com/go-i2p/crypto/ed25519"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
)

// KeyCertificate represents an I2P Key Certificate structure
// https://geti2p.net/spec/common-structures#certificate
// Accurate for version 0.9.24
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

	key_certificate = buildKeyCertificate(cert, spkType, cpkType)

	return
}

// parseBaseCertificate reads and validates the base certificate structure.
// Returns the parsed certificate, remaining bytes, and any error encountered.
func parseBaseCertificate(bytes []byte) (*certificate.Certificate, []byte, error) {
	cert, remainder, err := certificate.ReadCertificate(bytes)
	if err != nil {
		log.WithError(err).Error("Failed to read Certificate")
		return cert, remainder, err
	}
	return cert, remainder, nil
}

// validateKeyCertificateType validates that the certificate is specifically a Key Certificate type.
// Only CERT_KEY type certificates can be converted to KeyCertificate structures.
func validateKeyCertificateType(cert *certificate.Certificate) error {
	kind, err := cert.Type()
	if err != nil {
		log.WithFields(logger.Fields{"at": "validateKeyCertificateType", "reason": "invalid certificate type"}).Error(err.Error())
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
	log.Println("Certificate Data in NewKeyCertificate: ", certData[0:2], certData[2:4])
	return nil
}

// extractKeyTypes extracts the signing public key type and crypto public key type from certificate data.
// Returns the signing key type and crypto key type as I2P Integers.
func extractKeyTypes(certData []byte) (data.Integer, data.Integer) {
	spkType, _ := data.ReadInteger(certData[0:2], 2)
	cpkType, _ := data.ReadInteger(certData[2:4], 2)
	log.Println("cpkType in NewKeyCertificate: ", cpkType.Int(), "spkType in NewKeyCertificate: ", spkType.Int())
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

	keyCert := buildKeyCertificate(cert, spkType, cpkType)
	return keyCert, nil
}

// logExtractedKeyTypes logs detailed debug information about extracted key types.
func logExtractedKeyTypes(certData []byte, spkType, cpkType data.Integer) {
	/*log.WithFields(logger.Fields{
		"data_length": len(certData),
	}).Debug("Certificate Data Length in KeyCertificateFromCertificate")
	log.WithFields(logger.Fields{
		"cert_data": certData,
	}).Debug("Certificate Data Bytes in KeyCertificateFromCertificate")
	log.WithFields(logger.Fields{
		"cpk_type_bytes": certData[2:4],
	}).Debug("cpkTypeBytes in KeyCertificateFromCertificate")
	log.WithFields(logger.Fields{
		"spk_type_bytes": certData[0:2],
	}).Debug("spkTypeBytes in KeyCertificateFromCertificate")
	log.WithFields(logger.Fields{
		"cpk_type_int": cpkType.Int(),
	}).Debug("cpkType (Int) in KeyCertificateFromCertificate")
	log.WithFields(logger.Fields{
		"spk_type_int": spkType.Int(),
	}).Debug("spkType (Int) in KeyCertificateFromCertificate")*/
}

// Data returns the raw []byte contained in the Certificate.
func (keyCertificate KeyCertificate) Data() ([]byte, error) {
	data := keyCertificate.Certificate.RawBytes()
	log.WithFields(logger.Fields{
		"data_length": len(data),
	}).Debug("Retrieved raw data from keyCertificate")
	return keyCertificate.Certificate.RawBytes(), nil
}

// SigningPublicKeyType returns the signingPublicKey type as a Go integer.
func (keyCertificate KeyCertificate) SigningPublicKeyType() (signing_pubkey_type int) {
	signing_pubkey_type = keyCertificate.SpkType.Int()
	log.WithFields(logger.Fields{
		"signing_pubkey_type": signing_pubkey_type,
	}).Debug("Retrieved signingPublicKey type")
	return keyCertificate.SpkType.Int()
}

// PublicKeyType returns the publicKey type as a Go integer.
func (keyCertificate KeyCertificate) PublicKeyType() (pubkey_type int) {
	pubkey_type = keyCertificate.CpkType.Int()
	log.WithFields(logger.Fields{
		"pubkey_type": pubkey_type,
	}).Debug("Retrieved publicKey type")
	return keyCertificate.CpkType.Int()
}

// ConstructPublicKey returns a publicKey constructed using any excess data that may be stored in the KeyCertificate.
// Returns any errors encountered while parsing.
func (keyCertificate KeyCertificate) ConstructPublicKey(data []byte) (public_key types.ReceivingPublicKey, err error) {
	log.WithFields(logger.Fields{
		"input_length": len(data),
	}).Debug("Constructing publicKey from keyCertificate")
	key_type := keyCertificate.PublicKeyType()
	data_len := len(data)
	// Validate that input data contains sufficient bytes for the expected key size
	// This check prevents buffer underruns when extracting key material from certificate data
	if data_len < keyCertificate.CryptoSize() {
		log.WithFields(logger.Fields{
			"at":           "(keyCertificate) ConstructPublicKey",
			"data_len":     data_len,
			"required_len": KEYCERT_PUBKEY_SIZE,
			"reason":       "not enough data",
		}).Error("error constructing public key")
		err = oops.Errorf("error constructing public key: not enough data")
		return
	}
	// Switch on key type to construct the appropriate public key structure
	// Each case handles the specific key format and size requirements for that algorithm
	switch key_type {
	case KEYCERT_CRYPTO_ELG:
		// Extract ElGamal public key from the end of the data buffer
		// ElGamal keys are positioned at the end to maintain backwards compatibility
		var elg_key elgamal.ElgPublicKey
		copy(elg_key[:], data[KEYCERT_PUBKEY_SIZE-KEYCERT_CRYPTO_ELG_SIZE:KEYCERT_PUBKEY_SIZE])
		public_key = elg_key
		log.Debug("Constructed ElgPublicKey")
	case KEYCERT_CRYPTO_X25519:
		// Extract X25519 public key for modern Curve25519 encryption
		// X25519 provides high-performance elliptic curve Diffie-Hellman key exchange
		var curve25519_key curve25519.Curve25519PublicKey
		copy(curve25519_key[:], data[KEYCERT_PUBKEY_SIZE-KEYCERT_CRYPTO_X25519_SIZE:KEYCERT_PUBKEY_SIZE])
		public_key = curve25519_key
		log.Debug("Constructed Curve25519PublicKey")
	default:
		// Return an explicit error for unsupported key types
		// Unknown key types may indicate version incompatibility or corrupted data
		log.WithFields(logger.Fields{
			"key_type": key_type,
		}).Warn("Unknown public key type")
		err = oops.Errorf("unsupported crypto key type: %d", key_type)
	}

	return
}

// CryptoPublicKeySize returns the size of a public key for the certificate's crypto type
func (keyCertificate *KeyCertificate) CryptoPublicKeySize() (int, error) {
	size, exists := CryptoPublicKeySizes[uint16(keyCertificate.CpkType.Int())]
	if !exists {
		return 0, oops.Errorf("unknown crypto key type: %d", keyCertificate.CpkType.Int())
	}
	return size, nil
}

// SigningPublicKeySize returns the size of a signing public key for the certificate's signing type
func (keyCertificate *KeyCertificate) SigningPublicKeySize() int {
	spk_type := keyCertificate.SpkType
	switch spk_type.Int() {
	case SIGNATURE_TYPE_DSA_SHA1:
		log.Debug("Returning DSA_SHA1")
		return 128
	case signature.SIGNATURE_TYPE_ECDSA_SHA256_P256:
		log.Debug("Returning ECDSA_SHA256_P256")
		return 64
	case signature.SIGNATURE_TYPE_ECDSA_SHA384_P384:
		return 96
	case signature.SIGNATURE_TYPE_ECDSA_SHA512_P521:
		return 132
	case signature.SIGNATURE_TYPE_RSA_SHA256_2048:
		return 256
	case signature.SIGNATURE_TYPE_RSA_SHA384_3072:
		return 384
	case signature.SIGNATURE_TYPE_RSA_SHA512_4096:
		return 512
	case SIGNATURE_TYPE_ED25519_SHA512:
		return 32
	case KEYCERT_SIGN_ED25519PH:
		return 32
	case KEYCERT_SIGN_REDDSA_ED25519:
		return 32
	default:
		return 128
	}
}

// validateSigningKeyData validates that sufficient data is available for signing key construction.
// Returns an error if the data length is insufficient for the required signature size.
func validateSigningKeyData(dataLen, requiredSize int) error {
	if dataLen < requiredSize {
		log.WithFields(logger.Fields{
			"at":           "validateSigningKeyData",
			"data_len":     dataLen,
			"required_len": KEYCERT_SPK_SIZE,
			"reason":       "not enough data",
		}).Error("error constructing signing public key")
		return oops.Errorf("error constructing signing public key: not enough data")
	}
	return nil
}

// constructDSAKey constructs a DSA-SHA1 signing public key from certificate data.
// Legacy DSA-SHA1 signing key construction for backwards compatibility.
// Accepts either padded data (128 bytes, key at end) or raw key data (128 bytes exact).
func constructDSAKey(data []byte) (types.SigningPublicKey, error) {
	if len(data) < KEYCERT_SIGN_DSA_SHA1_SIZE {
		return nil, oops.Errorf("insufficient data for DSA key: expected at least %d bytes, got %d",
			KEYCERT_SIGN_DSA_SHA1_SIZE, len(data))
	}
	var dsa_key dsa.DSAPublicKey
	if len(data) >= KEYCERT_SPK_SIZE {
		// Padded format: extract key from the end of the 128-byte field
		copy(dsa_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_DSA_SHA1_SIZE:KEYCERT_SPK_SIZE])
	} else {
		// Raw key data
		copy(dsa_key[:], data[:KEYCERT_SIGN_DSA_SHA1_SIZE])
	}
	log.Debug("Constructed DSAPublicKey")
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
	log.Debug("Constructed P256PublicKey")
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
	log.Debug("Constructed P384PublicKey")
	return ec_p384_key, nil
}

// constructEd25519Key constructs an Ed25519 signing public key from certificate data.
// Ed25519 provides excellent security with 32-byte keys and fast verification.
// The input data should be exactly 32 bytes (the Ed25519 public key).
func constructEd25519Key(data []byte) (types.SigningPublicKey, error) {
	// For Ed25519, we expect exactly 32 bytes
	if len(data) != KEYCERT_SIGN_ED25519_SIZE {
		return nil, oops.Errorf("invalid Ed25519 key data length: expected %d, got %d",
			KEYCERT_SIGN_ED25519_SIZE, len(data))
	}

	// Create Ed25519PublicKey from the bytes using safe constructor
	ed25519_key, err := ed25519.NewEd25519PublicKey(data)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct Ed25519 public key")
	}
	log.Debug("Constructed Ed25519PublicKey")
	return ed25519_key, nil
}

// constructEd25519PHKey constructs an Ed25519ph (pre-hashed) signing public key from certificate data.
// Uses the same key format as Ed25519 but with pre-hashing for efficiency.
// The input data should be exactly 32 bytes (the Ed25519 public key).
func constructEd25519PHKey(data []byte) (types.SigningPublicKey, error) {
	// For Ed25519ph, we expect exactly 32 bytes
	if len(data) != KEYCERT_SIGN_ED25519PH_SIZE {
		return nil, oops.Errorf("invalid Ed25519ph key data length: expected %d, got %d",
			KEYCERT_SIGN_ED25519PH_SIZE, len(data))
	}

	// Create Ed25519PublicKey from the bytes using safe constructor
	ed25519ph_key, err := ed25519.NewEd25519PublicKey(data)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct Ed25519ph public key")
	}
	log.Debug("Constructed Ed25519PHPublicKey")
	return ed25519ph_key, nil
}

// ConstructSigningPublicKey returns a SingingPublicKey constructed using any excess data that may be stored in the KeyCertificate.
// Returns any errors encountered while parsing.
func (keyCertificate KeyCertificate) ConstructSigningPublicKey(data []byte) (signing_public_key types.SigningPublicKey, err error) {
	log.WithFields(logger.Fields{
		"input_length": len(data),
	}).Debug("Constructing signingPublicKey from keyCertificate")

	signing_key_type := keyCertificate.SigningPublicKeyType()
	logSigningKeyDebug(signing_key_type, len(data))

	if err = validateSigningKeyData(len(data), keyCertificate.SigningPublicKeySize()); err != nil {
		return
	}

	signing_public_key, err = selectSigningKeyConstructor(signing_key_type, data)
	return
}

// logSigningKeyDebug logs debug information about the signing key construction.
func logSigningKeyDebug(signing_key_type int, data_len int) {
	log.WithFields(logger.Fields{
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
		return nil, oops.Errorf("unimplemented signing key type: P521 (type %d)", KEYCERT_SIGN_P521)
	case KEYCERT_SIGN_RSA2048:
		return nil, oops.Errorf("unimplemented signing key type: RSA2048 (type %d)", KEYCERT_SIGN_RSA2048)
	case KEYCERT_SIGN_RSA3072:
		return nil, oops.Errorf("unimplemented signing key type: RSA3072 (type %d)", KEYCERT_SIGN_RSA3072)
	case KEYCERT_SIGN_RSA4096:
		return nil, oops.Errorf("unimplemented signing key type: RSA4096 (type %d)", KEYCERT_SIGN_RSA4096)
	case KEYCERT_SIGN_ED25519:
		return constructEd25519Key(data)
	case KEYCERT_SIGN_ED25519PH:
		return constructEd25519PHKey(data)
	case KEYCERT_SIGN_REDDSA_ED25519:
		// RedDSA uses the same key format as Ed25519
		return constructEd25519Key(data)
	default:
		log.WithFields(logger.Fields{
			"signing_key_type": signing_key_type,
		}).Warn("Unknown signing key type")
		return nil, oops.Errorf("unknown signing key type: %d", signing_key_type)
	}
}

// SignatureSize return the size of a Signature corresponding to the Key Certificate's signingPublicKey type.
// This returns the actual signature size (not the signing public key size).
// For signing public key sizes, use SigningPublicKeySize().
func (keyCertificate KeyCertificate) SignatureSize() (size int) {
	key_type := keyCertificate.SigningPublicKeyType()
	// Use the authoritative SigningKeySizes map which has correct signature sizes
	info, exists := SigningKeySizes[key_type]
	if !exists {
		log.WithFields(logger.Fields{
			"key_type": key_type,
		}).Warn("Unknown signing key type for signature size lookup")
		return 0
	}
	log.WithFields(logger.Fields{
		"key_type":       key_type,
		"signature_size": info.SignatureSize,
	}).Debug("Retrieved signature size")
	return info.SignatureSize
}

// CryptoSize return the size of a Public Key corresponding to the Key Certificate's publicKey type.
func (keyCertificate KeyCertificate) CryptoSize() (size int) {
	key_type := keyCertificate.PublicKeyType()
	// Use the authoritative CryptoKeySizes map which includes all spec-defined types
	info, exists := CryptoKeySizes[key_type]
	if !exists {
		log.WithFields(logger.Fields{
			"key_type": key_type,
		}).Warn("Unknown crypto key type for size lookup")
		return 0
	}
	log.WithFields(logger.Fields{
		"key_type":    key_type,
		"crypto_size": info.CryptoPublicKeySize,
	}).Debug("Retrieved crypto size")
	return info.CryptoPublicKeySize
}
