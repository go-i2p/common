// Package keys_and_cert implements the I2P KeysAndCert common data structure
package keys_and_cert

import (
	"github.com/go-i2p/crypto/ed25519"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/common/certificate"
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

// Validate checks if the KeysAndCert is fully initialized.
// Returns an error if any required field is nil or invalid.
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

// Bytes returns the entire keyCertificate in []byte form, trims payload to specified length.
// Returns an error if the KeysAndCert is not fully initialized.
func (keys_and_cert KeysAndCert) Bytes() ([]byte, error) {
	if err := keys_and_cert.Validate(); err != nil {
		return nil, err
	}

	bytes := []byte{}
	rpublen := 0
	if keys_and_cert.ReceivingPublic != nil {
		bytes = append(bytes, keys_and_cert.ReceivingPublic.Bytes()...)
		rpublen = len(keys_and_cert.ReceivingPublic.Bytes())
	}
	// bytes = append(bytes, keys_and_cert.ReceivingPublic.Bytes()...)
	padlen := 0
	if keys_and_cert.Padding != nil {
		bytes = append(bytes, keys_and_cert.Padding...)
		padlen = len(keys_and_cert.Padding)
	}
	// bytes = append(bytes, keys_and_cert.Padding...)
	spublen := 0
	if keys_and_cert.SigningPublic != nil {
		bytes = append(bytes, keys_and_cert.SigningPublic.Bytes()...)
		spublen = len(keys_and_cert.SigningPublic.Bytes())
	}
	// bytes = append(bytes, keys_and_cert.SigningPublic.Bytes()...)
	certlen := 0
	if keys_and_cert.KeyCertificate != nil {
		bytes = append(bytes, keys_and_cert.KeyCertificate.Bytes()...)
		certlen = len(keys_and_cert.KeyCertificate.Bytes())
	}
	// bytes = append(bytes, keys_and_cert.KeyCertificate.Bytes()...)
	log.WithFields(logger.Fields{
		"bytes":                bytes,
		"padding":              keys_and_cert.Padding,
		"bytes_length":         len(bytes),
		"pk_bytes_length":      rpublen,
		"padding_bytes_length": padlen,
		"spk_bytes_length":     spublen,
		"cert_bytes_length":    certlen,
	}).Debug("Retrieved bytes from KeysAndCert")
	return bytes, nil
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
func constructPublicKeyFromCert(keyCert *key_certificate.KeyCertificate, data []byte) (types.ReceivingPublicKey, error) {
	pubKeySize := keyCert.CryptoSize()
	pubKey, err := keyCert.ConstructPublicKey(data[:pubKeySize])
	if err != nil {
		log.WithError(err).Error("Failed to construct publicKey")
		return nil, err
	}
	return pubKey, nil
}

// extractPaddingFromData extracts padding bytes based on key sizes.
// Returns padding slice or nil if no padding is required.
func extractPaddingFromData(data []byte, pubKeySize, sigKeySize int) []byte {
	paddingSize := KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	if paddingSize > 0 {
		padding := make([]byte, paddingSize)
		copy(padding, data[pubKeySize:pubKeySize+paddingSize])
		return padding
	}
	return nil
}

// constructSigningKeyFromCert constructs a signing public key using data and the key certificate.
// Returns the constructed signing key or error if construction fails.
func constructSigningKeyFromCert(keyCert *key_certificate.KeyCertificate, data []byte, sigKeySize int) (types.SigningPublicKey, error) {
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
	publicKeyData := data[:pubKeySize]
	if len(publicKeyData) != pubKeySize {
		err := oops.Errorf("invalid ElGamal public key length")
		log.WithError(err).Error("Invalid ElGamal public key length")
		return nil, err
	}
	var elgPublicKey elgamal.ElgPublicKey
	copy(elgPublicKey[:], publicKeyData)
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
	signingPubKeyData := data[offset : offset+sigKeySize]
	if len(signingPubKeyData) != sigKeySize {
		err := oops.Errorf("invalid Ed25519 public key length")
		log.WithError(err).Error("Invalid Ed25519 public key length")
		return nil, err
	}
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
