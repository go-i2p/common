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

	// Validate cookie length
	if len(authCookie) != 32 {
		return nil, oops.Errorf("invalid cookie length: expected 32, got %d", len(authCookie))
	}

	// Extract X25519 private key
	// IMPORTANT: We need to keep privKey as pointer for SharedKey() call
	var privKey *x25519.PrivateKey
	if pk, ok := privateKey.(*x25519.PrivateKey); ok {
		privKey = pk
	} else if pk, ok := privateKey.(x25519.PrivateKey); ok {
		// Handle value type (e.g., from recipientPriv[:])
		privKey = &pk
	} else if privKeyBytes, ok := privateKey.([]byte); ok {
		if len(privKeyBytes) != x25519.PrivateKeySize {
			return nil, oops.Errorf("invalid private key length: expected %d, got %d",
				x25519.PrivateKeySize, len(privKeyBytes))
		}
		pk := x25519.PrivateKey{}
		copy(pk[:], privKeyBytes)
		privKey = &pk
	} else {
		return nil, oops.Errorf("invalid private key type: expected *x25519.PrivateKey, x25519.PrivateKey, or 32-byte []byte")
	}

	// Encrypted data format:
	// [ephemeral_public_key (32)] [nonce (12)] [ciphertext] [tag (16)]
	if len(els.encryptedInnerData) < x25519.PublicKeySize+chacha20poly1305.NonceSize+chacha20poly1305.TagSize {
		return nil, oops.Errorf("encrypted data too short: need at least %d bytes, got %d",
			x25519.PublicKeySize+chacha20poly1305.NonceSize+chacha20poly1305.TagSize,
			len(els.encryptedInnerData))
	}

	// Extract ephemeral public key (first 32 bytes)
	ephemeralPubBytes := els.encryptedInnerData[:x25519.PublicKeySize]

	log.WithField("ephemeral_pub", ephemeralPubBytes).Debug("Extracted ephemeral public key")

	// Perform X25519 ECDH to derive shared secret
	// Use the bytes directly - recreating x25519.PublicKey from bytes doesn't work
	sharedSecret, err := privKey.SharedKey(ephemeralPubBytes)
	if err != nil {
		log.WithError(err).Error("X25519 key exchange failed")
		return nil, oops.Errorf("X25519 ECDH failed: %w", err)
	}

	log.Debug("Derived shared secret via X25519 ECDH")

	// Derive encryption key using HKDF-SHA256
	// Input: shared secret (32 bytes) + cookie (32 bytes)
	// Purpose: PurposeEncryptedLeaseSetEncryption
	// Output: 32-byte ChaCha20-Poly1305 key
	var rootKey [32]byte
	copy(rootKey[:], sharedSecret)

	kd := kdf.NewKeyDerivation(rootKey)
	derivedKey, err := kd.DeriveForPurpose(kdf.PurposeEncryptedLeaseSetEncryption)
	if err != nil {
		log.WithError(err).Error("Key derivation failed")
		return nil, oops.Errorf("HKDF key derivation failed: %w", err)
	}

	log.Debug("Derived encryption key using HKDF-SHA256")

	// Create ChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.NewAEAD(derivedKey)
	if err != nil {
		log.WithError(err).Error("Failed to create AEAD cipher")
		return nil, oops.Errorf("ChaCha20-Poly1305 initialization failed: %w", err)
	}

	// Extract nonce (12 bytes after ephemeral public key)
	offset := x25519.PublicKeySize
	nonce := els.encryptedInnerData[offset : offset+chacha20poly1305.NonceSize]

	// Extract ciphertext + tag (everything after nonce)
	ciphertextWithTag := els.encryptedInnerData[offset+chacha20poly1305.NonceSize:]

	// Split ciphertext and tag
	if len(ciphertextWithTag) < chacha20poly1305.TagSize {
		return nil, oops.Errorf("ciphertext too short: need at least %d bytes for tag", chacha20poly1305.TagSize)
	}
	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-chacha20poly1305.TagSize]
	var tag [chacha20poly1305.TagSize]byte
	copy(tag[:], ciphertextWithTag[len(ciphertextWithTag)-chacha20poly1305.TagSize:])

	log.WithFields(logger.Fields{
		"nonce_length":      len(nonce),
		"ciphertext_length": len(ciphertext),
		"tag_length":        len(tag),
	}).Debug("Extracted encryption components")

	// Decrypt using ChaCha20-Poly1305 with empty associated data
	plaintext, err := aead.Decrypt(ciphertext, tag[:], nil, nonce)
	if err != nil {
		log.WithError(err).Warn("Decryption failed - invalid key or tampered data")
		return nil, oops.Errorf("ChaCha20-Poly1305 decryption failed: %w", err)
	}

	log.WithField("plaintext_length", len(plaintext)).Debug("Successfully decrypted inner data")

	// Parse decrypted data as LeaseSet2
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

	// Serialize LeaseSet2 to bytes
	plaintext, err := ls2.Bytes()
	if err != nil {
		log.WithError(err).Error("Failed to serialize LeaseSet2")
		return nil, oops.Errorf("LeaseSet2 serialization failed: %w", err)
	}

	log.WithField("plaintext_length", len(plaintext)).Debug("Serialized LeaseSet2")

	// Convert recipientPublicKey to []byte for SharedKey
	// IMPORTANT: We cannot create x25519.PublicKey from bytes - it breaks validation
	// Instead, we extract bytes and use them directly in SharedKey()
	var recipientPubBytes []byte
	if pub, ok := recipientPublicKey.(*x25519.PublicKey); ok {
		recipientPubBytes = (*pub)[:]
	} else if pub, ok := recipientPublicKey.(x25519.PublicKey); ok {
		// Handle value type (e.g., from recipientPub[:])
		recipientPubBytes = pub[:]
	} else if c25519Pub, ok := recipientPublicKey.(curve25519.Curve25519PublicKey); ok {
		if len(c25519Pub) != x25519.PublicKeySize {
			return nil, oops.Errorf("invalid Curve25519PublicKey length: expected %d, got %d",
				x25519.PublicKeySize, len(c25519Pub))
		}
		recipientPubBytes = []byte(c25519Pub)
	} else if pubKeyBytes, ok := recipientPublicKey.([]byte); ok {
		if len(pubKeyBytes) != x25519.PublicKeySize {
			return nil, oops.Errorf("invalid public key length: expected %d, got %d",
				x25519.PublicKeySize, len(pubKeyBytes))
		}
		recipientPubBytes = pubKeyBytes
	} else {
		return nil, oops.Errorf("invalid public key type: expected *x25519.PublicKey, x25519.PublicKey, Curve25519PublicKey, or 32-byte []byte")
	}

	// Generate ephemeral X25519 key pair for this encryption
	ephemeralPub, ephemeralPriv, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		log.WithError(err).Error("Failed to generate ephemeral key pair")
		return nil, oops.Errorf("ephemeral key generation failed: %w", err)
	}

	log.Debug("Generated ephemeral X25519 key pair")

	// Perform X25519 ECDH to derive shared secret
	// CRITICAL: Use recipientPubBytes directly - DO NOT create x25519.PublicKey from bytes
	sharedSecret, err := ephemeralPriv.SharedKey(recipientPubBytes)
	if err != nil {
		log.WithError(err).Error("X25519 key exchange failed")
		return nil, oops.Errorf("X25519 ECDH failed: %w", err)
	}

	log.Debug("Derived shared secret via X25519 ECDH")

	// Derive encryption key using HKDF-SHA256
	// Input: shared secret (32 bytes) + cookie (32 bytes)
	// Purpose: PurposeEncryptedLeaseSetEncryption
	// Output: 32-byte ChaCha20-Poly1305 key
	var rootKey [32]byte
	copy(rootKey[:], sharedSecret)

	kd := kdf.NewKeyDerivation(rootKey)
	derivedKey, err := kd.DeriveForPurpose(kdf.PurposeEncryptedLeaseSetEncryption)
	if err != nil {
		log.WithError(err).Error("Key derivation failed")
		return nil, oops.Errorf("HKDF key derivation failed: %w", err)
	}

	log.Debug("Derived encryption key using HKDF-SHA256")

	// Create ChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.NewAEAD(derivedKey)
	if err != nil {
		log.WithError(err).Error("Failed to create AEAD cipher")
		return nil, oops.Errorf("ChaCha20-Poly1305 initialization failed: %w", err)
	}

	// Generate random 12-byte nonce
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		log.WithError(err).Error("Failed to generate random nonce")
		return nil, oops.Errorf("nonce generation failed: %w", err)
	}

	log.WithField("nonce", nonce).Debug("Generated random nonce")

	// Encrypt using ChaCha20-Poly1305 with empty associated data
	ciphertext, tag, err := aead.Encrypt(plaintext, nil, nonce)
	if err != nil {
		log.WithError(err).Error("Encryption failed")
		return nil, oops.Errorf("ChaCha20-Poly1305 encryption failed: %w", err)
	}

	log.WithFields(logger.Fields{
		"ciphertext_length": len(ciphertext),
		"tag_length":        len(tag),
	}).Debug("Encrypted plaintext")

	// Construct encrypted data: [ephemeral_pub(32)][nonce(12)][ciphertext][tag(16)]
	encryptedData := make([]byte, 0, x25519.PublicKeySize+chacha20poly1305.NonceSize+len(ciphertext)+chacha20poly1305.TagSize)
	encryptedData = append(encryptedData, ephemeralPub[:]...)
	encryptedData = append(encryptedData, nonce...)
	encryptedData = append(encryptedData, ciphertext...)
	encryptedData = append(encryptedData, tag[:]...)

	log.WithField("encrypted_length", len(encryptedData)).Info("Successfully encrypted LeaseSet2")

	return encryptedData, nil
}
