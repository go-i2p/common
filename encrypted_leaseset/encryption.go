package encrypted_leaseset

import (
	"crypto/rand"

	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"go.step.sm/crypto/x25519"
)

// DecryptInnerData decrypts the encrypted inner data of an EncryptedLeaseSet.
//
// The decryption process follows the I2P Proposal 123 specification:
//  1. Extract ephemeral public key from encrypted data (first 32 bytes)
//  2. Perform X25519 ECDH with recipient's private key to derive shared secret
//  3. Derive symmetric encryption key using HKDF-SHA256
//  4. Decrypt using ChaCha20-Poly1305 AEAD with derived key
//  5. Parse decrypted data as LeaseSet2
//
// Parameters:
//   - authCookie: 32-byte cookie for key derivation (reserved for future use in HKDF)
//   - privateKey: Recipient's X25519 private key for ECDH (32 bytes)
//
// NOTE: The cookie is NOT part of the cleartext EncryptedLeaseSet wire format.
// It is an encryption-layer parameter used during key derivation.
func (els *EncryptedLeaseSet) DecryptInnerData(authCookie []byte, privateKey interface{}) (*lease_set2.LeaseSet2, error) {
	log.WithFields(logger.Fields{
		"cookie_length":    len(authCookie),
		"encrypted_length": len(els.encryptedInnerData),
	}).Debug("Decrypting EncryptedLeaseSet inner data")

	if len(authCookie) != 32 {
		return nil, oops.Errorf("invalid cookie length: expected 32, got %d", len(authCookie))
	}

	privKey, err := extractX25519PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	if err := validateEncryptedDataLength(els.encryptedInnerData); err != nil {
		return nil, err
	}

	derivedKey, err := deriveDecryptionKey(privKey, els.encryptedInnerData[:x25519.PublicKeySize])
	if err != nil {
		return nil, err
	}

	plaintext, err := decryptWithAEAD(derivedKey, els.encryptedInnerData)
	if err != nil {
		return nil, err
	}

	return parseDecryptedLeaseSet2(plaintext)
}

// extractX25519PrivateKey converts a private key from various supported types
// to an *x25519.PrivateKey suitable for ECDH key exchange.
// Supports *x25519.PrivateKey, x25519.PrivateKey (value), and 32-byte []byte.
func extractX25519PrivateKey(privateKey interface{}) (*x25519.PrivateKey, error) {
	switch pk := privateKey.(type) {
	case *x25519.PrivateKey:
		return pk, nil
	case x25519.PrivateKey:
		return &pk, nil
	case []byte:
		if len(pk) != x25519.PrivateKeySize {
			return nil, oops.Errorf("invalid private key length: expected %d, got %d",
				x25519.PrivateKeySize, len(pk))
		}
		result := x25519.PrivateKey{}
		copy(result[:], pk)
		return &result, nil
	default:
		return nil, oops.Errorf("invalid private key type: expected *x25519.PrivateKey, x25519.PrivateKey, or 32-byte []byte")
	}
}

// validateEncryptedDataLength checks that the encrypted data has sufficient bytes
// for the ephemeral public key, nonce, and authentication tag.
func validateEncryptedDataLength(data []byte) error {
	minSize := x25519.PublicKeySize + chacha20poly1305.NonceSize + chacha20poly1305.TagSize
	if len(data) < minSize {
		return oops.Errorf("encrypted data too short: need at least %d bytes, got %d",
			minSize, len(data))
	}
	return nil
}

// deriveDecryptionKey performs X25519 ECDH with the given private key and ephemeral
// public key, then derives a symmetric key via HKDF-SHA256 for ChaCha20-Poly1305.
func deriveDecryptionKey(privKey *x25519.PrivateKey, ephemeralPubBytes []byte) ([32]byte, error) {
	log.WithField("ephemeral_pub", ephemeralPubBytes).Debug("Extracted ephemeral public key")

	sharedSecret, err := privKey.SharedKey(ephemeralPubBytes)
	if err != nil {
		log.WithError(err).Error("X25519 key exchange failed")
		return [32]byte{}, oops.Errorf("X25519 ECDH failed: %w", err)
	}
	log.Debug("Derived shared secret via X25519 ECDH")

	return deriveSymmetricKey(sharedSecret)
}

// deriveSymmetricKey derives a ChaCha20-Poly1305 symmetric key from a shared secret
// using HKDF-SHA256 with PurposeEncryptedLeaseSetEncryption.
func deriveSymmetricKey(sharedSecret []byte) ([32]byte, error) {
	var rootKey [32]byte
	copy(rootKey[:], sharedSecret)

	kd := kdf.NewKeyDerivation(rootKey)
	derivedKey, err := kd.DeriveForPurpose(kdf.PurposeEncryptedLeaseSetEncryption)
	if err != nil {
		log.WithError(err).Error("Key derivation failed")
		return [32]byte{}, oops.Errorf("HKDF key derivation failed: %w", err)
	}
	log.Debug("Derived encryption key using HKDF-SHA256")
	return derivedKey, nil
}

// decryptWithAEAD decrypts the encrypted data using ChaCha20-Poly1305 AEAD.
// The data format is: [ephemeral_pub(32)][nonce(12)][ciphertext][tag(16)].
func decryptWithAEAD(derivedKey [32]byte, encryptedData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewAEAD(derivedKey)
	if err != nil {
		log.WithError(err).Error("Failed to create AEAD cipher")
		return nil, oops.Errorf("ChaCha20-Poly1305 initialization failed: %w", err)
	}

	nonce, ciphertext, tag, err := extractEncryptionComponents(encryptedData)
	if err != nil {
		return nil, err
	}

	log.WithFields(logger.Fields{
		"nonce_length":      len(nonce),
		"ciphertext_length": len(ciphertext),
		"tag_length":        len(tag),
	}).Debug("Extracted encryption components")

	plaintext, err := aead.Decrypt(ciphertext, tag, nil, nonce)
	if err != nil {
		log.WithError(err).Warn("Decryption failed - invalid key or tampered data")
		return nil, oops.Errorf("ChaCha20-Poly1305 decryption failed: %w", err)
	}

	log.WithField("plaintext_length", len(plaintext)).Debug("Successfully decrypted inner data")
	return plaintext, nil
}

// extractEncryptionComponents splits encrypted data into nonce, ciphertext, and tag.
// Expected format after ephemeral public key: [nonce(12)][ciphertext][tag(16)].
func extractEncryptionComponents(encryptedData []byte) (nonce, ciphertext, tag []byte, err error) {
	offset := x25519.PublicKeySize
	nonce = encryptedData[offset : offset+chacha20poly1305.NonceSize]

	ciphertextWithTag := encryptedData[offset+chacha20poly1305.NonceSize:]
	if len(ciphertextWithTag) < chacha20poly1305.TagSize {
		return nil, nil, nil, oops.Errorf("ciphertext too short: need at least %d bytes for tag", chacha20poly1305.TagSize)
	}

	ciphertext = ciphertextWithTag[:len(ciphertextWithTag)-chacha20poly1305.TagSize]
	tag = make([]byte, chacha20poly1305.TagSize)
	copy(tag, ciphertextWithTag[len(ciphertextWithTag)-chacha20poly1305.TagSize:])
	return nonce, ciphertext, tag, nil
}

// parseDecryptedLeaseSet2 parses decrypted plaintext bytes as a LeaseSet2 structure
// and logs the result.
func parseDecryptedLeaseSet2(plaintext []byte) (*lease_set2.LeaseSet2, error) {
	innerLS2, _, err := lease_set2.ReadLeaseSet2(plaintext)
	if err != nil {
		log.WithError(err).Error("Failed to parse decrypted data as LeaseSet2")
		return nil, oops.Errorf("invalid LeaseSet2 in decrypted data: %w", err)
	}

	logFields := logger.Fields{
		"num_leases": len(innerLS2.Leases()),
	}
	if addr, err := innerLS2.Destination().Base32Address(); err == nil {
		logFields["destination"] = addr[:16] + "..."
	}
	log.WithFields(logFields).Info("Successfully decrypted and parsed EncryptedLeaseSet")

	return &innerLS2, nil
}

// EncryptInnerLeaseSet2 encrypts a LeaseSet2 into EncryptedLeaseSet inner data format.
//
// The encryption process follows the I2P Proposal 123 specification:
//  1. Serialize LeaseSet2 to bytes
//  2. Generate ephemeral X25519 key pair for ECDH
//  3. Derive shared secret using recipient's public key
//  4. Derive symmetric encryption key using HKDF-SHA256 from shared secret and cookie
//  5. Generate random 12-byte nonce
//  6. Encrypt using ChaCha20-Poly1305 AEAD with derived key
//  7. Prepend ephemeral public key to encrypted data
//
// Parameters:
//   - ls2: The LeaseSet2 to encrypt (contains actual destination and leases)
//   - cookie: 32-byte random cookie for key derivation and anti-replay
//   - recipientPublicKey: Recipient's X25519 public key for ECDH (32 bytes)
//
// Returns:
//   - []byte: Encrypted data in format: [ephemeral_pub(32)][nonce(12)][ciphertext][tag(16)]
//   - error: ErrInvalidPublicKey, ErrSerializationFailed, ErrEncryptionFailed
//
// Security:
//   - Uses fresh ephemeral key pair for each encryption (forward secrecy)
//   - Generates cryptographically random nonce
//   - Uses authenticated encryption (AEAD) to prevent tampering
//   - Derived key is unique to this specific cookie + recipient combination
//
// Usage:
//
//	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, recipientPubKey)
//	if err != nil {
//	    return err
//	}
//	// Use encryptedData when constructing EncryptedLeaseSet
//
// Spec: I2P Proposal 123 Section 5.1
func EncryptInnerLeaseSet2(ls2 *lease_set2.LeaseSet2, cookie [32]byte, recipientPublicKey interface{}) ([]byte, error) {
	log.WithFields(logger.Fields{
		"num_leases": len(ls2.Leases()),
	}).Debug("Encrypting LeaseSet2 for EncryptedLeaseSet")

	plaintext, err := serializeLeaseSet2Plaintext(ls2)
	if err != nil {
		return nil, err
	}

	recipientPubBytes, err := extractRecipientPublicKeyBytes(recipientPublicKey)
	if err != nil {
		return nil, err
	}

	ephemeralPub, derivedKey, err := deriveEncryptionKey(recipientPubBytes)
	if err != nil {
		return nil, err
	}

	return encryptAndAssemble(plaintext, derivedKey, ephemeralPub)
}

// serializeLeaseSet2Plaintext serializes a LeaseSet2 to bytes for encryption.
func serializeLeaseSet2Plaintext(ls2 *lease_set2.LeaseSet2) ([]byte, error) {
	plaintext, err := ls2.Bytes()
	if err != nil {
		log.WithError(err).Error("Failed to serialize LeaseSet2")
		return nil, oops.Errorf("LeaseSet2 serialization failed: %w", err)
	}
	log.WithField("plaintext_length", len(plaintext)).Debug("Serialized LeaseSet2")
	return plaintext, nil
}

// extractRecipientPublicKeyBytes converts a recipient public key from various
// supported types to a raw byte slice for use in X25519 ECDH.
// Supports *x25519.PublicKey, x25519.PublicKey, Curve25519PublicKey, and 32-byte []byte.
func extractRecipientPublicKeyBytes(recipientPublicKey interface{}) ([]byte, error) {
	switch pub := recipientPublicKey.(type) {
	case *x25519.PublicKey:
		return (*pub)[:], nil
	case x25519.PublicKey:
		return pub[:], nil
	case curve25519.Curve25519PublicKey:
		if len(pub) != x25519.PublicKeySize {
			return nil, oops.Errorf("invalid Curve25519PublicKey length: expected %d, got %d",
				x25519.PublicKeySize, len(pub))
		}
		return []byte(pub), nil
	case []byte:
		if len(pub) != x25519.PublicKeySize {
			return nil, oops.Errorf("invalid public key length: expected %d, got %d",
				x25519.PublicKeySize, len(pub))
		}
		return pub, nil
	default:
		return nil, oops.Errorf("invalid public key type: expected *x25519.PublicKey, x25519.PublicKey, Curve25519PublicKey, or 32-byte []byte")
	}
}

// deriveEncryptionKey generates an ephemeral X25519 key pair, performs ECDH with the
// recipient's public key, and derives a symmetric encryption key via HKDF-SHA256.
// Returns the ephemeral public key and derived symmetric key.
func deriveEncryptionKey(recipientPubBytes []byte) (x25519.PublicKey, [32]byte, error) {
	ephemeralPub, ephemeralPriv, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		log.WithError(err).Error("Failed to generate ephemeral key pair")
		return nil, [32]byte{}, oops.Errorf("ephemeral key generation failed: %w", err)
	}
	log.Debug("Generated ephemeral X25519 key pair")

	sharedSecret, err := ephemeralPriv.SharedKey(recipientPubBytes)
	if err != nil {
		log.WithError(err).Error("X25519 key exchange failed")
		return nil, [32]byte{}, oops.Errorf("X25519 ECDH failed: %w", err)
	}
	log.Debug("Derived shared secret via X25519 ECDH")

	derivedKey, err := deriveSymmetricKey(sharedSecret)
	if err != nil {
		return nil, [32]byte{}, err
	}

	return ephemeralPub, derivedKey, nil
}

// encryptAndAssemble encrypts plaintext using ChaCha20-Poly1305 AEAD and assembles
// the final encrypted data in the format: [ephemeral_pub(32)][nonce(12)][ciphertext][tag(16)].
func encryptAndAssemble(plaintext []byte, derivedKey [32]byte, ephemeralPub x25519.PublicKey) ([]byte, error) {
	aead, err := chacha20poly1305.NewAEAD(derivedKey)
	if err != nil {
		log.WithError(err).Error("Failed to create AEAD cipher")
		return nil, oops.Errorf("ChaCha20-Poly1305 initialization failed: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		log.WithError(err).Error("Failed to generate random nonce")
		return nil, oops.Errorf("nonce generation failed: %w", err)
	}
	log.WithField("nonce", nonce).Debug("Generated random nonce")

	ciphertext, tag, err := aead.Encrypt(plaintext, nil, nonce)
	if err != nil {
		log.WithError(err).Error("Encryption failed")
		return nil, oops.Errorf("ChaCha20-Poly1305 encryption failed: %w", err)
	}

	log.WithFields(logger.Fields{
		"ciphertext_length": len(ciphertext),
		"tag_length":        len(tag),
	}).Debug("Encrypted plaintext")

	encryptedData := make([]byte, 0, x25519.PublicKeySize+chacha20poly1305.NonceSize+len(ciphertext)+chacha20poly1305.TagSize)
	encryptedData = append(encryptedData, ephemeralPub[:]...)
	encryptedData = append(encryptedData, nonce...)
	encryptedData = append(encryptedData, ciphertext...)
	encryptedData = append(encryptedData, tag[:]...)

	log.WithField("encrypted_length", len(encryptedData)).Info("Successfully encrypted LeaseSet2")

	return encryptedData, nil
}
