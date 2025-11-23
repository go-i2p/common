// Package key_certificate implements the I2P Destination common data structure
package key_certificate

import (
	"fmt"

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

	// Parse the base certificate structure first to extract type and payload
	// This validates the certificate header and extracts the key-specific data
	var cert certificate.Certificate
	cert, remainder, err = certificate.ReadCertificate(bytes)
	if err != nil {
		log.WithError(err).Error("Failed to read Certificate")
		return
	}

	// Validate that this is specifically a Key Certificate type
	// Only CERT_KEY type certificates can be converted to KeyCertificate structures
	kind, err := cert.Type()
	if err != nil {
		log.WithFields(logger.Fields{"at": "NewKeyCertificate", "reason": "invalid certificate type"}).Error(err.Error())
		return nil, remainder, err
	}
	if kind != certificate.CERT_KEY {
		return nil, remainder, oops.Errorf("invalid certificate type: %d", kind)
	}

	// Ensure the certificate payload contains sufficient data for key type fields
	// Key certificates require at least 4 bytes: 2 for signing key type, 2 for crypto key type
	certData, err := cert.Data()
	if err != nil {
		return nil, remainder, err
	}
	if len(certData) < 4 {
		return nil, remainder, oops.Errorf("key certificate data too short")
	}
	log.Println("Certificate Data in NewKeyCertificate: ", certData[0:2], certData[2:4])

	// Extract the signing public key type from the first 2 bytes of certificate data
	// This determines which signature algorithm will be used for this certificate
	spkType, _ := data.ReadInteger(certData[0:2], 2)
	// Extract the crypto public key type from bytes 2-3 of certificate data
	// This determines which encryption algorithm will be used for this certificate
	cpkType, _ := data.ReadInteger(certData[2:4], 2)
	key_certificate = &KeyCertificate{
		Certificate: cert,
		CpkType:     cpkType,
		SpkType:     spkType,
	}
	log.Println("cpkType in NewKeyCertificate: ", cpkType.Int(), "spkType in NewKeyCertificate: ", spkType.Int())

	log.WithFields(logger.Fields{
		"spk_type":         key_certificate.SpkType.Int(),
		"cpk_type":         key_certificate.CpkType.Int(),
		"remainder_length": len(remainder),
	}).Debug("Successfully created new keyCertificate")

	return
}

// KeyCertificateFromCertificate creates a KeyCertificate from an existing Certificate
func KeyCertificateFromCertificate(cert certificate.Certificate) (*KeyCertificate, error) {
	// Validate certificate type before proceeding with conversion
	// Only Key Certificate types contain the required key type information
	kind, err := cert.Type()
	if err != nil {
		log.WithFields(logger.Fields{"at": "KeyCertificateFromCertificate", "reason": "invalid certificate type"}).Error(err.Error())
	}
	if kind != certificate.CERT_KEY {
		return nil, oops.Errorf("expected Key Certificate type, got %d", kind)
	}

	certdata, err := cert.Data()
	if err != nil {
		return nil, err
	}
	fmt.Printf("Certificate Data Length in KeyCertificateFromCertificate: %d\n", len(certdata))
	fmt.Printf("Certificate Data Bytes in KeyCertificateFromCertificate: %v\n", certdata)

	// Ensure certificate contains minimum required data for key type extraction
	// Key certificates need at least 4 bytes for signing and crypto key type identifiers
	if len(certdata) < 4 {
		return nil, oops.Errorf("certificate payload too short in KeyCertificateFromCertificate")
	}

	// Extract raw bytes for signing public key type (first 2 bytes)
	// This identifies which signature algorithm is specified in the certificate
	spkTypeBytes := certdata[0:2]
	// Extract raw bytes for crypto public key type (next 2 bytes)
	// This identifies which encryption algorithm is specified in the certificate
	cpkTypeBytes := certdata[2:4]

	fmt.Printf("cpkTypeBytes in KeyCertificateFromCertificate: %v\n", cpkTypeBytes)
	fmt.Printf("spkTypeBytes in KeyCertificateFromCertificate: %v\n", spkTypeBytes)

	// Convert raw bytes to I2P Integer types for algorithm identification
	// These integers will be used to determine key sizes and construction methods
	spkType := data.Integer(spkTypeBytes)
	cpkType := data.Integer(cpkTypeBytes)

	fmt.Printf("cpkType (Int) in KeyCertificateFromCertificate: %d\n", cpkType.Int())
	fmt.Printf("spkType (Int) in KeyCertificateFromCertificate: %d\n", spkType.Int())

	// Construct the KeyCertificate with extracted type information
	// This creates a specialized certificate that can construct cryptographic keys
	keyCert := &KeyCertificate{
		Certificate: cert,
		CpkType:     cpkType,
		SpkType:     spkType,
	}

	return keyCert, nil
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
		// Log warning for unsupported key types to aid in debugging
		// Unknown key types may indicate version incompatibility or corrupted data
		log.WithFields(logger.Fields{
			"key_type": key_type,
		}).Warn("Unknown public key type")
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
func constructDSAKey(data []byte) types.SigningPublicKey {
	var dsa_key dsa.DSAPublicKey
	copy(dsa_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_DSA_SHA1_SIZE:KEYCERT_SPK_SIZE])
	log.Debug("Constructed DSAPublicKey")
	return dsa_key
}

// constructECDSAP256Key constructs an ECDSA P-256 signing public key from certificate data.
// Provides 128-bit security level with compact 64-byte keys.
func constructECDSAP256Key(data []byte) types.SigningPublicKey {
	var ec_p256_key ecdsa.ECP256PublicKey
	copy(ec_p256_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_P256_SIZE:KEYCERT_SPK_SIZE])
	log.Debug("Constructed P256PublicKey")
	return ec_p256_key
}

// constructECDSAP384Key constructs an ECDSA P-384 signing public key from certificate data.
// Provides 192-bit security level with 96-byte keys.
func constructECDSAP384Key(data []byte) types.SigningPublicKey {
	var ec_p384_key ecdsa.ECP384PublicKey
	copy(ec_p384_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_P384_SIZE:KEYCERT_SPK_SIZE])
	log.Debug("Constructed P384PublicKey")
	return ec_p384_key
}

// constructEd25519Key constructs an Ed25519 signing public key from certificate data.
// Ed25519 provides excellent security with 32-byte keys and fast verification.
func constructEd25519Key(data []byte) types.SigningPublicKey {
	var ed25519_key ed25519.Ed25519PublicKey
	copy(ed25519_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_ED25519_SIZE:KEYCERT_SPK_SIZE])
	log.Debug("Constructed Ed25519PublicKey")
	return ed25519_key
}

// constructEd25519PHKey constructs an Ed25519ph (pre-hashed) signing public key from certificate data.
// Uses the same key format as Ed25519 but with pre-hashing for efficiency.
func constructEd25519PHKey(data []byte) types.SigningPublicKey {
	var ed25519ph_key ed25519.Ed25519PublicKey
	copy(ed25519ph_key[:], data[KEYCERT_SPK_SIZE-KEYCERT_SIGN_ED25519PH_SIZE:KEYCERT_SPK_SIZE])
	log.Debug("Constructed Ed25519PHPublicKey")
	return ed25519ph_key
}

// ConstructSigningPublicKey returns a SingingPublicKey constructed using any excess data that may be stored in the KeyCertificate.
// Returns any errors encountered while parsing.
func (keyCertificate KeyCertificate) ConstructSigningPublicKey(data []byte) (signing_public_key types.SigningPublicKey, err error) {
	log.WithFields(logger.Fields{
		"input_length": len(data),
	}).Debug("Constructing signingPublicKey from keyCertificate")
	signing_key_type := keyCertificate.SigningPublicKeyType()
	log.WithFields(logger.Fields{
		"signing_key_type": signing_key_type,
		"data_len":         len(data),
		"required_len":     KEYCERT_SPK_SIZE,
	}).Error("DEBUG: About to construct signing public key")

	if err = validateSigningKeyData(len(data), keyCertificate.SignatureSize()); err != nil {
		return
	}

	switch signing_key_type {
	case KEYCERT_SIGN_DSA_SHA1:
		signing_public_key = constructDSAKey(data)
	case KEYCERT_SIGN_P256:
		signing_public_key = constructECDSAP256Key(data)
	case KEYCERT_SIGN_P384:
		signing_public_key = constructECDSAP384Key(data)
	case KEYCERT_SIGN_P521:
		panic("unimplemented P521SigningPublicKey")
	case KEYCERT_SIGN_RSA2048:
		panic("unimplemented RSA2048SigningPublicKey")
	case KEYCERT_SIGN_RSA3072:
		panic("unimplemented RSA3072SigningPublicKey")
	case KEYCERT_SIGN_RSA4096:
		panic("unimplemented RSA4096SigningPublicKey")
	case KEYCERT_SIGN_ED25519:
		signing_public_key = constructEd25519Key(data)
	case KEYCERT_SIGN_ED25519PH:
		signing_public_key = constructEd25519PHKey(data)
	default:
		log.WithFields(logger.Fields{
			"signing_key_type": signing_key_type,
		}).Warn("Unknown signing key type")
		return nil, oops.Errorf("unknown signing key type")
	}

	return
}

// SignatureSize return the size of a Signature corresponding to the Key Certificate's signingPublicKey type.
func (keyCertificate KeyCertificate) SignatureSize() (size int) {
	// Create a lookup map for signature sizes based on algorithm type
	// This provides O(1) lookup time and centralizes size information for maintainability
	sizes := map[int]int{
		KEYCERT_SIGN_DSA_SHA1:  KEYCERT_SIGN_DSA_SHA1_SIZE,
		KEYCERT_SIGN_P256:      KEYCERT_SIGN_P256_SIZE,
		KEYCERT_SIGN_P384:      KEYCERT_SIGN_P384_SIZE,
		KEYCERT_SIGN_P521:      KEYCERT_SIGN_P521_SIZE,
		KEYCERT_SIGN_RSA2048:   KEYCERT_SIGN_RSA2048_SIZE,
		KEYCERT_SIGN_RSA3072:   KEYCERT_SIGN_RSA3072_SIZE,
		KEYCERT_SIGN_RSA4096:   KEYCERT_SIGN_RSA4096_SIZE,
		KEYCERT_SIGN_ED25519:   KEYCERT_SIGN_ED25519_SIZE,
		KEYCERT_SIGN_ED25519PH: KEYCERT_SIGN_ED25519PH_SIZE,
	}
	key_type := keyCertificate.SigningPublicKeyType()
	// Look up the signature size with existence check to handle unknown types
	// This prevents returning invalid sizes for unsupported or corrupted key types
	size, exists := sizes[key_type]
	if !exists {
		log.WithFields(logger.Fields{
			"key_type": key_type,
		}).Warn("Unknown signing key type")
		return 0 // Or handle error appropriately
	}
	log.WithFields(logger.Fields{
		"key_type":       key_type,
		"signature_size": size,
	}).Debug("Retrieved signature size")
	return size
}

// CryptoSize return the size of a Public Key corresponding to the Key Certificate's publicKey type.
func (keyCertificate KeyCertificate) CryptoSize() (size int) {
	// Create a lookup map for crypto key sizes based on algorithm type
	// This mapping ensures correct buffer allocation for different encryption algorithms
	sizes := map[int]int{
		KEYCERT_CRYPTO_ELG:    KEYCERT_CRYPTO_ELG_SIZE,
		KEYCERT_CRYPTO_P256:   KEYCERT_CRYPTO_P256_SIZE,
		KEYCERT_CRYPTO_P384:   KEYCERT_CRYPTO_P384_SIZE,
		KEYCERT_CRYPTO_P521:   KEYCERT_CRYPTO_P521_SIZE,
		KEYCERT_CRYPTO_X25519: KEYCERT_CRYPTO_X25519_SIZE,
	}
	key_type := keyCertificate.PublicKeyType()
	// Direct map lookup for crypto size (note: no existence check in original)
	// The original implementation assumes all key types are valid, but this could be enhanced
	size = sizes[int(key_type)]
	log.WithFields(logger.Fields{
		"key_type":    key_type,
		"crypto_size": size,
	}).Debug("Retrieved crypto size")
	return size
}
