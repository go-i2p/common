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
	sigKeySize := keyCertificate.SignatureSize()

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
func (keys_and_cert KeysAndCert) Bytes() []byte {
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
	return bytes
}

// PublicKey returns the public key as a types.publicKey.
func (keys_and_cert *KeysAndCert) PublicKey() (key types.ReceivingPublicKey) {
	return keys_and_cert.ReceivingPublic
}

// SigningPublicKey returns the signing public key.
func (keys_and_cert *KeysAndCert) SigningPublicKey() (signing_public_key types.SigningPublicKey) {
	return keys_and_cert.SigningPublic
}

// Certificate returns the certificate.
func (keys_and_cert *KeysAndCert) Certificate() (cert certificate.Certificate) {
	return keys_and_cert.KeyCertificate.Certificate
}

// ReadKeysAndCert creates a new *KeysAndCert from []byte using ReadKeysAndCert.
// Returns a pointer to KeysAndCert unlike ReadKeysAndCert.
func ReadKeysAndCert(data []byte) (*KeysAndCert, []byte, error) {
	log.WithFields(logger.Fields{
		"input_length": len(data),
	}).Debug("Reading KeysAndCert from data")
	var err error
	var remainder []byte
	var keys_and_cert KeysAndCert

	data_len := len(data)
	if data_len < KEYS_AND_CERT_MIN_SIZE {
		log.WithFields(logger.Fields{
			"at":           "ReadKeysAndCert",
			"data_len":     data_len,
			"required_len": KEYS_AND_CERT_MIN_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing keys and cert")
		err = oops.Errorf("error parsing KeysAndCert: data is smaller than minimum valid size")
		return &keys_and_cert, remainder, err
	}

	keys_and_cert.KeyCertificate, remainder, err = key_certificate.NewKeyCertificate(data[KEYS_AND_CERT_DATA_SIZE:])
	if err != nil {
		log.WithError(err).Error("Failed to create keyCertificate")
		return &keys_and_cert, remainder, err
	}

	// Get the actual key sizes from the certificate
	pubKeySize := keys_and_cert.KeyCertificate.CryptoSize()
	sigKeySize := keys_and_cert.KeyCertificate.SignatureSize()

	// Construct public key
	keys_and_cert.ReceivingPublic, err = keys_and_cert.KeyCertificate.ConstructPublicKey(data[:pubKeySize])
	if err != nil {
		log.WithError(err).Error("Failed to construct publicKey")
		return &keys_and_cert, remainder, err
	}

	// Calculate padding size and extract padding
	paddingSize := KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	if paddingSize > 0 {
		keys_and_cert.Padding = make([]byte, paddingSize)
		copy(keys_and_cert.Padding, data[pubKeySize:pubKeySize+paddingSize])
	}

	// Construct signing public key
	keys_and_cert.SigningPublic, err = keys_and_cert.KeyCertificate.ConstructSigningPublicKey(
		data[KEYS_AND_CERT_DATA_SIZE-sigKeySize : KEYS_AND_CERT_DATA_SIZE],
	)
	if err != nil {
		log.WithError(err).Error("Failed to construct signingPublicKey")
		return &keys_and_cert, remainder, err
	}

	log.WithFields(logger.Fields{
		"public_key_type":         keys_and_cert.KeyCertificate.PublicKeyType(),
		"signing_public_key_type": keys_and_cert.KeyCertificate.SigningPublicKeyType(),
		"padding_length":          len(keys_and_cert.Padding),
		"remainder_length":        len(remainder),
	}).Debug("Successfully read KeysAndCert")

	return &keys_and_cert, remainder, err
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
	return ed25519.Ed25519PublicKey(signingPubKeyData), nil
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

// ReadKeysAndCertElgAndEd25519 reads KeysAndCert with fixed ElGamal and Ed25519 key sizes.
func ReadKeysAndCertElgAndEd25519(data []byte) (keysAndCert *KeysAndCert, remainder []byte, err error) {
	log.WithFields(logger.Fields{
		"input_length": len(data),
	}).Debug("Reading KeysAndCert from data")

	const (
		pubKeySize    = 256
		sigKeySize    = 32
		totalKeySize  = 384
		paddingSize   = totalKeySize - pubKeySize - sigKeySize
		minDataLength = totalKeySize + 3
	)

	if err = validateMinimumDataLength(len(data), minDataLength); err != nil {
		return
	}

	keysAndCert = &KeysAndCert{}

	keysAndCert.ReceivingPublic, err = extractElGamalPublicKey(data, pubKeySize)
	if err != nil {
		return
	}

	paddingStart := pubKeySize
	paddingEnd := paddingStart + paddingSize
	keysAndCert.Padding = extractPaddingData(data, paddingStart, paddingEnd)

	keysAndCert.SigningPublic, err = extractEd25519SigningKey(data, paddingEnd, sigKeySize)
	if err != nil {
		return
	}

	keysAndCert.KeyCertificate, remainder, err = extractKeyCertificate(data, totalKeySize)
	if err != nil {
		return
	}

	log.WithFields(logger.Fields{
		"public_key_type":         "ElGamal",
		"signing_public_key_type": "Ed25519",
		"padding_length":          len(keysAndCert.Padding),
		"remainder_length":        len(remainder),
	}).Debug("Successfully read KeysAndCert")

	return
}
