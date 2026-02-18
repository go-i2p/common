// Package keys_and_cert implements the I2P KeysAndCert common data structure
package keys_and_cert

import (
	"crypto/rand"

	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/common/certificate"
	i2pdata "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/crypto/types"
)

var log = logger.GetGoI2PLogger()

/*
[KeysAndCert]
Accurate for version 0.9.67

Description
An encryption public key, a signing public key, and a certificate, used as either a RouterIdentity or a Destination.

Contents
A publicKey followed by a signingPublicKey and then a Certificate.

+----+----+----+----+----+----+----+----+
| public_key                            |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| padding (optional)                    |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| signing_key                           |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| certificate                           |
+----+----+----+-//

public_key :: publicKey (partial or full)
              length -> 256 bytes or as specified in key certificate

padding :: random data
              length -> 0 bytes or as specified in key certificate
              padding length + signing_key length == 128 bytes

signing__key :: signingPublicKey (partial or full)
              length -> 128 bytes or as specified in key certificate
              padding length + signing_key length == 128 bytes

certificate :: Certificate
               length -> >= 3 bytes

total length: 387+ bytes
*/

// KeysAndCert is the represenation of an I2P KeysAndCert.
//
// https://geti2p.net/spec/common-structures#keysandcert
type KeysAndCert struct {
	KeyCertificate  *key_certificate.KeyCertificate
	ReceivingPublic types.ReceivingPublicKey
	Padding         []byte
	SigningPublic   types.SigningPublicKey
}

// NewKeysAndCert creates a new KeysAndCert instance with the provided parameters.
// It validates the sizes of the provided keys and padding before assembling the struct.
func NewKeysAndCert(
	keyCertificate *key_certificate.KeyCertificate,
	publicKey types.ReceivingPublicKey,
	padding []byte,
	signingPublicKey types.SigningPublicKey,
) (*KeysAndCert, error) {
	log.Debug("Creating new KeysAndCert with provided parameters")

	if keyCertificate == nil {
		log.Error("KeyCertificate is nil")
		return nil, oops.Errorf("KeyCertificate cannot be nil")
	}

	// Get actual key sizes from certificate
	pubKeySize := keyCertificate.CryptoSize()
	sigKeySize := keyCertificate.SigningPublicKeySize()

	// Validate public key size
	if err := validatePublicKeySize(publicKey, pubKeySize); err != nil {
		return nil, err
	}

	// Validate signing key size
	if err := validateSigningKeySize(signingPublicKey, sigKeySize); err != nil {
		return nil, err
	}

	// Validate padding size
	if err := validatePaddingSize(padding, pubKeySize, sigKeySize); err != nil {
		return nil, err
	}

	keysAndCert := &KeysAndCert{
		KeyCertificate:  keyCertificate,
		ReceivingPublic: publicKey,
		Padding:         padding,
		SigningPublic:   signingPublicKey,
	}

	/*log.WithFields(logger.Fields{
		"public_key_length":         publicKey.Len(),
		"signing_public_key_length": signingPublicKey.Len(),
		"padding_length":            len(padding),
	}).Debug("Successfully created KeysAndCert")*/

	return keysAndCert, nil
}

// Validate checks if the KeysAndCert is fully initialized and consistent.
// Returns an error if any required field is nil, or if key sizes don't match
// the KeyCertificate key types.
func (kac *KeysAndCert) Validate() error {
	if kac == nil {
		return oops.Errorf("KeysAndCert is nil")
	}
	if kac.KeyCertificate == nil {
		return oops.Errorf("KeyCertificate is required")
	}
	if kac.ReceivingPublic == nil {
		return oops.Errorf("ReceivingPublic key is required")
	}
	if kac.SigningPublic == nil {
		return oops.Errorf("SigningPublic key is required")
	}
	// Verify key sizes match the certificate's declared types
	expectedCryptoSize := kac.KeyCertificate.CryptoSize()
	if expectedCryptoSize > 0 && kac.ReceivingPublic.Len() != expectedCryptoSize {
		return oops.Errorf(
			"ReceivingPublic key size mismatch: certificate declares %d bytes, key has %d bytes",
			expectedCryptoSize, kac.ReceivingPublic.Len(),
		)
	}
	expectedSigSize := kac.KeyCertificate.SigningPublicKeySize()
	if expectedSigSize > 0 && kac.SigningPublic.Len() != expectedSigSize {
		return oops.Errorf(
			"SigningPublic key size mismatch: certificate declares %d bytes, key has %d bytes",
			expectedSigSize, kac.SigningPublic.Len(),
		)
	}
	return nil
}

// IsValid returns true if the KeysAndCert is fully initialized.
// This is a convenience method that calls Validate() and returns false if there's an error.
func (kac *KeysAndCert) IsValid() bool {
	return kac.Validate() == nil
}

// validatePublicKeySize validates that the public key has the expected size.
// Returns error if the key is non-nil and has an incorrect size.
func validatePublicKeySize(publicKey types.ReceivingPublicKey, expectedSize int) error {
	if publicKey != nil {
		if publicKey.Len() != expectedSize {
			log.WithFields(logger.Fields{
				"expected_size": expectedSize,
				"actual_size":   publicKey.Len(),
			}).Error("Invalid publicKey size")
			return oops.Errorf("publicKey has invalid size: expected %d, got %d", expectedSize, publicKey.Len())
		}
	}
	return nil
}

// validateSigningKeySize validates that the signing public key has the expected size.
// Returns error if the key is non-nil and has an incorrect size.
func validateSigningKeySize(signingPublicKey types.SigningPublicKey, expectedSize int) error {
	if signingPublicKey != nil {
		if signingPublicKey.Len() != expectedSize {
			log.WithFields(logger.Fields{
				"expected_size": expectedSize,
				"actual_size":   signingPublicKey.Len(),
			}).Error("Invalid signingPublicKey size")
			return oops.Errorf("signingPublicKey has invalid size: expected %d, got %d", expectedSize, signingPublicKey.Len())
		}
	}
	return nil
}

// validatePaddingSize validates that the padding has the expected size based on key sizes.
// Returns error if the padding size is incorrect.
func validatePaddingSize(padding []byte, pubKeySize, sigKeySize int) error {
	expectedPaddingSize := KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	if len(padding) != expectedPaddingSize {
		log.WithFields(logger.Fields{
			"expected_size": expectedPaddingSize,
			"actual_size":   len(padding),
		}).Error("Invalid padding size")
		return oops.Errorf("invalid padding size")
	}
	return nil
}

// Bytes returns the entire keyCertificate in []byte form as wire-format bytes.
// Crypto keys are start-aligned and signing keys are right-justified per the I2P specification.
// Returns an error if the KeysAndCert is not fully initialized.
func (keys_and_cert *KeysAndCert) Bytes() ([]byte, error) {
	if err := keys_and_cert.Validate(); err != nil {
		return nil, err
	}

	block := buildKeysAndCertBlock(keys_and_cert)

	certBytes := keys_and_cert.KeyCertificate.Bytes()
	result := append(block, certBytes...)

	log.WithFields(logger.Fields{
		"bytes_length":         len(result),
		"pk_bytes_length":      len(keys_and_cert.ReceivingPublic.Bytes()),
		"padding_bytes_length": len(keys_and_cert.Padding),
		"spk_bytes_length":     len(keys_and_cert.SigningPublic.Bytes()),
		"cert_bytes_length":    len(certBytes),
	}).Debug("Retrieved bytes from KeysAndCert")
	return result, nil
}

// buildKeysAndCertBlock constructs the 384-byte wire format block with
// start-aligned crypto key and right-justified signing key, with padding in between.
func buildKeysAndCertBlock(kac *KeysAndCert) []byte {
	block := make([]byte, KEYS_AND_CERT_DATA_SIZE)

	pubKeySize := kac.KeyCertificate.CryptoSize()
	sigKeySize := kac.KeyCertificate.SigningPublicKeySize()
	pubPaddingSize := KEYS_AND_CERT_PUBKEY_SIZE - pubKeySize
	sigPaddingSize := KEYS_AND_CERT_SPK_SIZE - sigKeySize

	// Start-align public key in 256-byte field (per spec)
	if kac.ReceivingPublic != nil {
		pubBytes := kac.ReceivingPublic.Bytes()
		copy(block[0:len(pubBytes)], pubBytes)
	}
	// Public key field padding (after start-aligned key)
	if pubPaddingSize > 0 && kac.Padding != nil && len(kac.Padding) >= pubPaddingSize {
		copy(block[pubKeySize:KEYS_AND_CERT_PUBKEY_SIZE], kac.Padding[:pubPaddingSize])
	}
	// Signing key field padding (before right-justified key)
	if sigPaddingSize > 0 && kac.Padding != nil && len(kac.Padding) >= pubPaddingSize+sigPaddingSize {
		copy(block[KEYS_AND_CERT_PUBKEY_SIZE:KEYS_AND_CERT_PUBKEY_SIZE+sigPaddingSize],
			kac.Padding[pubPaddingSize:pubPaddingSize+sigPaddingSize])
	}
	// Right-justify signing key in 128-byte field
	if kac.SigningPublic != nil {
		sigBytes := kac.SigningPublic.Bytes()
		copy(block[KEYS_AND_CERT_DATA_SIZE-len(sigBytes):KEYS_AND_CERT_DATA_SIZE], sigBytes)
	}

	return block
}

// PublicKey returns the public key as a types.publicKey.
// Returns an error if the KeysAndCert is not fully initialized.
func (keys_and_cert *KeysAndCert) PublicKey() (types.ReceivingPublicKey, error) {
	if err := keys_and_cert.Validate(); err != nil {
		return nil, err
	}
	return keys_and_cert.ReceivingPublic, nil
}

// SigningPublicKey returns the signing public key.
// Returns an error if the KeysAndCert is not fully initialized.
func (keys_and_cert *KeysAndCert) SigningPublicKey() (types.SigningPublicKey, error) {
	if err := keys_and_cert.Validate(); err != nil {
		return nil, err
	}
	return keys_and_cert.SigningPublic, nil
}

// Certificate returns the certificate.
func (keys_and_cert *KeysAndCert) Certificate() *certificate.Certificate {
	return &keys_and_cert.KeyCertificate.Certificate
}

// ReadKeysAndCert creates a new *KeysAndCert from []byte using ReadKeysAndCert.
// Returns a pointer to KeysAndCert unlike ReadKeysAndCert.
// validateKeysAndCertDataSize validates that data meets minimum KeysAndCert size requirements.
// Returns error if data is too short to contain a valid KeysAndCert structure.
func validateKeysAndCertDataSize(dataLen int) error {
	if dataLen < KEYS_AND_CERT_MIN_SIZE {
		log.WithFields(logger.Fields{
			"at":           "validateKeysAndCertDataSize",
			"data_len":     dataLen,
			"required_len": KEYS_AND_CERT_MIN_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing keys and cert")
		return oops.Errorf("error parsing KeysAndCert: data is smaller than minimum valid size")
	}
	return nil
}

// parseKeyCertificateFromData parses a KeyCertificate from data at the specified offset.
// Returns the parsed certificate, remaining data, and any error encountered.
func parseKeyCertificateFromData(data []byte, offset int) (*key_certificate.KeyCertificate, []byte, error) {
	keyCert, remainder, err := key_certificate.NewKeyCertificate(data[offset:])
	if err != nil {
		log.WithError(err).Error("Failed to create keyCertificate")
		return nil, remainder, err
	}
	return keyCert, remainder, nil
}

// constructPublicKeyFromCert constructs a public key using data and the key certificate.
// Returns the constructed public key or error if construction fails.
// The full 256-byte public key region is passed to ConstructPublicKey, which extracts
// the actual key from its start-aligned position within the field.
func constructPublicKeyFromCert(keyCert *key_certificate.KeyCertificate, data []byte) (types.ReceivingPublicKey, error) {
	pubKeySize := keyCert.CryptoSize()
	if pubKeySize == 0 {
		return nil, oops.Errorf("unsupported or unknown crypto key type")
	}
	if len(data) < KEYS_AND_CERT_PUBKEY_SIZE {
		return nil, oops.Errorf("insufficient data for public key construction: need %d bytes, got %d", KEYS_AND_CERT_PUBKEY_SIZE, len(data))
	}
	pubKey, err := keyCert.ConstructPublicKey(data[:KEYS_AND_CERT_PUBKEY_SIZE])
	if err != nil {
		log.WithError(err).Error("Failed to construct publicKey")
		return nil, err
	}
	return pubKey, nil
}

// extractPaddingFromData extracts padding bytes based on key sizes.
// The padding consists of two regions in the 384-byte block:
//   - Public key field padding: bytes after the start-aligned crypto key in the 256-byte field
//   - Signing key field padding: bytes before the right-justified signing key in the 128-byte field
//
// Returns concatenated padding [pubKeyPadding || sigKeyPadding] or nil if no padding.
func extractPaddingFromData(data []byte, pubKeySize, sigKeySize int) []byte {
	paddingSize := KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	if paddingSize <= 0 {
		return nil
	}
	padding := make([]byte, paddingSize)
	pubPaddingSize := KEYS_AND_CERT_PUBKEY_SIZE - pubKeySize
	sigPaddingSize := KEYS_AND_CERT_SPK_SIZE - sigKeySize
	// Crypto key is start-aligned; padding follows at offset pubKeySize
	if pubPaddingSize > 0 {
		copy(padding[:pubPaddingSize], data[pubKeySize:KEYS_AND_CERT_PUBKEY_SIZE])
	}
	if sigPaddingSize > 0 {
		copy(padding[pubPaddingSize:], data[KEYS_AND_CERT_PUBKEY_SIZE:KEYS_AND_CERT_PUBKEY_SIZE+sigPaddingSize])
	}
	return padding
}

// constructSigningKeyFromCert constructs a signing public key using data and the key certificate.
// Returns the constructed signing key or error if construction fails.
// For signing keys <= 128 bytes, the key is right-justified in the last 128 bytes of the 384-byte block.
// For signing keys > 128 bytes, excess data would need to be read from the certificate payload
// (not yet implemented for legacy RSA types).
func constructSigningKeyFromCert(keyCert *key_certificate.KeyCertificate, data []byte, sigKeySize int) (types.SigningPublicKey, error) {
	if sigKeySize <= 0 {
		return nil, oops.Errorf("invalid signing key size: %d", sigKeySize)
	}
	if sigKeySize > KEYS_AND_CERT_SPK_SIZE {
		return nil, oops.Errorf(
			"signing key size %d exceeds inline capacity (%d bytes); excess certificate data reconstruction not implemented",
			sigKeySize, KEYS_AND_CERT_SPK_SIZE,
		)
	}
	sigKey, err := keyCert.ConstructSigningPublicKey(
		data[KEYS_AND_CERT_DATA_SIZE-sigKeySize : KEYS_AND_CERT_DATA_SIZE],
	)
	if err != nil {
		log.WithError(err).Error("Failed to construct signingPublicKey")
		return nil, err
	}
	return sigKey, nil
}

func ReadKeysAndCert(data []byte) (*KeysAndCert, []byte, error) {
	log.WithFields(logger.Fields{
		"input_length": len(data),
	}).Debug("Reading KeysAndCert from data")

	if err := validateKeysAndCertDataSize(len(data)); err != nil {
		return nil, nil, err
	}

	// Check certificate type before full parsing.
	// NULL certificates (type 0) imply ElGamal + DSA-SHA1 and need special handling.
	certType := int(data[KEYS_AND_CERT_DATA_SIZE])
	if certType != certificate.CERT_KEY {
		return readKeysAndCertNonKeyCert(data, certType)
	}

	keyCert, remainder, err := parseKeyCertificateFromData(data, KEYS_AND_CERT_DATA_SIZE)
	if err != nil {
		return nil, remainder, err
	}

	pubKey, err := constructPublicKeyFromCert(keyCert, data)
	if err != nil {
		return nil, remainder, err
	}

	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SigningPublicKeySize()
	padding := extractPaddingFromData(data, pubKeySize, sigKeySize)

	sigKey, err := constructSigningKeyFromCert(keyCert, data, sigKeySize)
	if err != nil {
		return nil, remainder, err
	}

	keysAndCert := &KeysAndCert{
		KeyCertificate:  keyCert,
		ReceivingPublic: pubKey,
		Padding:         padding,
		SigningPublic:   sigKey,
	}

	log.WithFields(logger.Fields{
		"public_key_type":         keyCert.PublicKeyType(),
		"signing_public_key_type": keyCert.SigningPublicKeyType(),
		"padding_length":          len(padding),
		"remainder_length":        len(remainder),
	}).Debug("Successfully read KeysAndCert")

	return keysAndCert, remainder, nil
}

// validateMinimumDataLength validates that the data has sufficient length for parsing.
// Returns an error if the data is smaller than the minimum required size.
func validateMinimumDataLength(dataLen, minDataLength int) error {
	if dataLen < minDataLength {
		err := oops.Errorf("error parsing KeysAndCert: data is smaller than minimum valid size, got %d bytes", dataLen)
		log.WithError(err).Error("Data is smaller than minimum valid size")
		return err
	}
	return nil
}

// extractElGamalPublicKey extracts and validates an ElGamal public key from the data.
// Returns the public key or an error if the data is invalid.
func extractElGamalPublicKey(data []byte, pubKeySize int) (types.ReceivingPublicKey, error) {
	if len(data) < pubKeySize {
		err := oops.Errorf("insufficient data for ElGamal public key: need %d bytes, got %d", pubKeySize, len(data))
		log.WithError(err).Error("Invalid ElGamal public key length")
		return nil, err
	}
	var elgPublicKey elgamal.ElgPublicKey
	copy(elgPublicKey[:], data[:pubKeySize])
	return elgPublicKey, nil
}

// extractPaddingData extracts padding bytes from the data at the specified range.
// Returns a copy of the padding data.
func extractPaddingData(data []byte, paddingStart, paddingEnd int) []byte {
	return data[paddingStart:paddingEnd]
}

// extractEd25519SigningKey extracts and validates an Ed25519 signing public key from the data.
// Returns the signing key or an error if the data is invalid.
func extractEd25519SigningKey(data []byte, offset, sigKeySize int) (types.SigningPublicKey, error) {
	if offset+sigKeySize > len(data) {
		err := oops.Errorf("insufficient data for Ed25519 signing key: need %d bytes at offset %d, got %d total", sigKeySize, offset, len(data))
		log.WithError(err).Error("Invalid Ed25519 public key length")
		return nil, err
	}
	signingPubKeyData := data[offset : offset+sigKeySize]
	ed25519Key, err := ed25519.NewEd25519PublicKey(signingPubKeyData)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct Ed25519 signing key")
	}
	return ed25519Key, nil
}

// extractKeyCertificate parses and extracts a KeyCertificate from the data.
// Returns the certificate, remaining data, and any error encountered.
func extractKeyCertificate(data []byte, totalKeySize int) (*key_certificate.KeyCertificate, []byte, error) {
	certData := data[totalKeySize:]
	keyCert, remainder, err := key_certificate.NewKeyCertificate(certData)
	if err != nil {
		log.WithError(err).Error("Failed to read keyCertificate")
		return nil, nil, err
	}
	return keyCert, remainder, nil
}

// logElgEd25519KeysDebug logs debug information for ElGamal/Ed25519 KeysAndCert parsing.
func logElgEd25519KeysDebug(dataLen int) {
	log.WithFields(logger.Fields{
		"input_length": dataLen,
	}).Debug("Reading KeysAndCert from data")
}

// getElgEd25519KeySizes returns the key sizes for ElGamal and Ed25519 keys.
func getElgEd25519KeySizes() (pubKeySize, sigKeySize, totalKeySize, paddingSize, minDataLength int) {
	pubKeySize = 256
	sigKeySize = 32
	totalKeySize = 384
	paddingSize = totalKeySize - pubKeySize - sigKeySize
	minDataLength = totalKeySize + 3
	return
}

// extractElgEd25519Keys extracts the ElGamal public key, padding, and Ed25519 signing key from data.
func extractElgEd25519Keys(data []byte, pubKeySize, paddingSize, sigKeySize int) (pubKey types.ReceivingPublicKey, padding []byte, sigKey types.SigningPublicKey, err error) {
	pubKey, err = extractElGamalPublicKey(data, pubKeySize)
	if err != nil {
		return
	}

	paddingStart := pubKeySize
	paddingEnd := paddingStart + paddingSize
	padding = extractPaddingData(data, paddingStart, paddingEnd)

	sigKey, err = extractEd25519SigningKey(data, paddingEnd, sigKeySize)
	return
}

// logElgEd25519Success logs successful parsing of ElGamal/Ed25519 KeysAndCert.
func logElgEd25519Success(paddingLen, remainderLen int) {
	log.WithFields(logger.Fields{
		"public_key_type":         "ElGamal",
		"signing_public_key_type": "Ed25519",
		"padding_length":          paddingLen,
		"remainder_length":        remainderLen,
	}).Debug("Successfully read KeysAndCert")
}

// ReadKeysAndCertElgAndEd25519 reads KeysAndCert with fixed ElGamal and Ed25519 key sizes.
func ReadKeysAndCertElgAndEd25519(data []byte) (keysAndCert *KeysAndCert, remainder []byte, err error) {
	logElgEd25519KeysDebug(len(data))

	pubKeySize, sigKeySize, totalKeySize, paddingSize, minDataLength := getElgEd25519KeySizes()

	if err = validateMinimumDataLength(len(data), minDataLength); err != nil {
		return
	}

	keysAndCert = &KeysAndCert{}
	keysAndCert.ReceivingPublic, keysAndCert.Padding, keysAndCert.SigningPublic, err = extractElgEd25519Keys(data, pubKeySize, paddingSize, sigKeySize)
	if err != nil {
		return
	}

	keysAndCert.KeyCertificate, remainder, err = extractKeyCertificate(data, totalKeySize)
	if err != nil {
		return
	}

	logElgEd25519Success(len(keysAndCert.Padding), len(remainder))
	return
}

// readKeysAndCertNonKeyCert handles parsing of KeysAndCert with non-KEY certificate types.
// Currently supports NULL certificates (type 0) which imply ElGamal + DSA-SHA1 keys.
// Returns an error for unsupported certificate types.
func readKeysAndCertNonKeyCert(rawData []byte, certType int) (*KeysAndCert, []byte, error) {
	if certType != certificate.CERT_NULL {
		return nil, nil, oops.Errorf("unsupported certificate type: %d (only NULL and KEY certificates are supported)", certType)
	}

	log.Debug("Parsing KeysAndCert with NULL certificate (ElGamal + DSA-SHA1)")

	// Parse the NULL certificate to get remainder
	cert, remainder, err := certificate.ReadCertificate(rawData[KEYS_AND_CERT_DATA_SIZE:])
	if err != nil {
		return nil, remainder, err
	}

	// NULL certificate implies ElGamal (type 0) + DSA-SHA1 (type 0)
	keyCert := buildNullCertKeyCertificate(cert)

	pubKey, err := constructPublicKeyFromCert(keyCert, rawData)
	if err != nil {
		return nil, remainder, err
	}

	sigKeySize := keyCert.SigningPublicKeySize()
	pubKeySize := keyCert.CryptoSize()
	padding := extractPaddingFromData(rawData, pubKeySize, sigKeySize)

	sigKey, err := constructSigningKeyFromCert(keyCert, rawData, sigKeySize)
	if err != nil {
		return nil, remainder, err
	}

	return &KeysAndCert{
		KeyCertificate:  keyCert,
		ReceivingPublic: pubKey,
		Padding:         padding,
		SigningPublic:   sigKey,
	}, remainder, nil
}

// buildNullCertKeyCertificate creates a synthetic KeyCertificate for NULL certificates.
// NULL certificates imply ElGamal (type 0) encryption + DSA-SHA1 (type 0) signing.
func buildNullCertKeyCertificate(cert *certificate.Certificate) *key_certificate.KeyCertificate {
	spkType := i2pdata.Integer([]byte{0x00, 0x00}) // DSA-SHA1 = 0
	cpkType := i2pdata.Integer([]byte{0x00, 0x00}) // ElGamal = 0
	return &key_certificate.KeyCertificate{
		Certificate: *cert,
		SpkType:     spkType,
		CpkType:     cpkType,
	}
}

// extractX25519PublicKey extracts an X25519 public key from the 256-byte public key field.
// The key is start-aligned in the field per the I2P specification.
func extractX25519PublicKey(data []byte) (types.ReceivingPublicKey, error) {
	if len(data) < KEYS_AND_CERT_PUBKEY_SIZE {
		return nil, oops.Errorf("insufficient data for X25519 key extraction: need %d bytes, got %d",
			KEYS_AND_CERT_PUBKEY_SIZE, len(data))
	}
	x25519Key := make(curve25519.Curve25519PublicKey, 32)
	copy(x25519Key, data[0:32])
	return x25519Key, nil
}

// getX25519Ed25519KeySizes returns the key sizes for X25519 and Ed25519 keys.
func getX25519Ed25519KeySizes() (pubKeySize, sigKeySize, totalKeySize, paddingSize, minDataLength int) {
	pubKeySize = 32
	sigKeySize = 32
	totalKeySize = 384
	paddingSize = totalKeySize - pubKeySize - sigKeySize
	minDataLength = totalKeySize + 3
	return
}

// ReadKeysAndCertX25519AndEd25519 reads KeysAndCert with fixed X25519 and Ed25519 key sizes.
// This is the modern recommended key combination for Router Identities since I2P 0.9.48.
func ReadKeysAndCertX25519AndEd25519(data []byte) (keysAndCert *KeysAndCert, remainder []byte, err error) {
	log.WithFields(logger.Fields{
		"input_length": len(data),
	}).Debug("Reading X25519+Ed25519 KeysAndCert from data")

	pubKeySize, sigKeySize, totalKeySize, _, minDataLength := getX25519Ed25519KeySizes()

	if err = validateMinimumDataLength(len(data), minDataLength); err != nil {
		return
	}

	keysAndCert = &KeysAndCert{}
	keysAndCert.ReceivingPublic, err = extractX25519PublicKey(data)
	if err != nil {
		return
	}

	keysAndCert.Padding = extractPaddingFromData(data, pubKeySize, sigKeySize)

	sigKeyOffset := totalKeySize - sigKeySize
	keysAndCert.SigningPublic, err = extractEd25519SigningKey(data, sigKeyOffset, sigKeySize)
	if err != nil {
		return
	}

	keysAndCert.KeyCertificate, remainder, err = extractKeyCertificate(data, totalKeySize)
	if err != nil {
		return
	}

	log.WithFields(logger.Fields{
		"public_key_type":         "X25519",
		"signing_public_key_type": "Ed25519",
		"padding_length":          len(keysAndCert.Padding),
		"remainder_length":        len(remainder),
	}).Debug("Successfully read X25519+Ed25519 KeysAndCert")
	return
}

// GenerateCompressiblePadding generates padding that is compressible per I2P Proposal 161.
// The padding is generated by repeating 32 bytes of random data, making it compressible
// in I2P protocols (I2NP, Streaming, SSU2) for bandwidth efficiency.
func GenerateCompressiblePadding(size int) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, oops.Wrapf(err, "failed to generate random padding seed")
	}
	padding := make([]byte, size)
	for i := 0; i < size; i += 32 {
		n := 32
		if i+n > size {
			n = size - i
		}
		copy(padding[i:i+n], seed[:n])
	}
	return padding, nil
}
