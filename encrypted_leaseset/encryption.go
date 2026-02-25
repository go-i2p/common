package encrypted_leaseset

import (
	"github.com/go-i2p/crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

// DeriveSubcredential computes the I2P subcredential for EncryptedLeaseSet
// encryption and decryption.
//
// Per the I2P spec (https://geti2p.net/spec/encryptedleaseset):
//
//	credential    = SHA-256("credential" || destSigningPubKey)
//	subcredential = SHA-256("subcredential" || credential || blindedPubKey)
//
// Parameters:
//   - destSigningPubKey: The unblinded destination signing public key
//     (32 bytes for Ed25519/RedDSA)
//   - blindedPubKey: The blinded signing public key from the EncryptedLeaseSet
//
// The subcredential binds the encryption to knowledge of the destination,
// so only clients who know the original destination can decrypt.
func DeriveSubcredential(destSigningPubKey, blindedPubKey []byte) [32]byte {
	credential := deriveCredential(destSigningPubKey)
	return deriveSubcredFromCredential(credential, blindedPubKey)
}

// deriveCredential computes: SHA-256("credential" || destSigningPubKey).
func deriveCredential(destSigningPubKey []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("credential"))
	h.Write(destSigningPubKey)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// deriveSubcredFromCredential computes:
// SHA-256("subcredential" || credential || blindedPubKey).
func deriveSubcredFromCredential(credential [32]byte, blindedPubKey []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("subcredential"))
	h.Write(credential[:])
	h.Write(blindedPubKey)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// buildLayerIKM constructs the HKDF input keying material:
// ikm = subcredential || published (4 bytes big-endian).
func buildLayerIKM(subcredential [32]byte, published uint32) []byte {
	ikm := make([]byte, 36)
	copy(ikm[:32], subcredential[:])
	binary.BigEndian.PutUint32(ikm[32:], published)
	return ikm
}

// deriveLayerKey derives a 32-byte symmetric key and 12-byte IV
// using HKDF-SHA256 with the given salt, IKM, and info string.
//
// Per I2P spec:
//
//	key_material = HKDF-SHA256(salt, ikm, info, 44)
//	key = key_material[0:32]
//	iv  = key_material[32:44]
func deriveLayerKey(salt, ikm []byte, info string) ([32]byte, [12]byte, error) {
	hkdfReader := hkdf.New(sha256.New, ikm, salt, []byte(info))
	keyMaterial := make([]byte, 44)
	if _, err := io.ReadFull(hkdfReader, keyMaterial); err != nil {
		return [32]byte{}, [12]byte{}, oops.Errorf(
			"HKDF key derivation failed: %w", err)
	}
	var key [32]byte
	var iv [12]byte
	copy(key[:], keyMaterial[:32])
	copy(iv[:], keyMaterial[32:])
	return key, iv, nil
}

// chacha20Crypt applies ChaCha20 stream cipher. Since ChaCha20 is its
// own inverse, this function handles both encryption and decryption.
func chacha20Crypt(key [32]byte, iv [12]byte, data []byte) ([]byte, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], iv[:])
	if err != nil {
		return nil, oops.Errorf("ChaCha20 cipher init failed: %w", err)
	}
	out := make([]byte, len(data))
	cipher.XORKeyStream(out, data)
	return out, nil
}

// DecryptInnerData decrypts the encrypted inner data using the I2P spec's
// two-layer ChaCha20 encryption scheme (no per-client auth).
//
// Decryption process:
//  1. Extract outerSalt (first 32 bytes, cleartext)
//  2. Derive Layer 1 key: HKDF(outerSalt, subcredential||published, "ELS2_L1K")
//  3. Decrypt Layer 1 → authType || innerSalt || layer2Ciphertext
//  4. Verify authType == 0 (no per-client auth)
//  5. Derive Layer 2 key: HKDF(innerSalt, subcredential||published, "ELS2_L2K")
//  6. Decrypt Layer 2 → InnerLeaseSet2
//
// Parameters:
//   - subcredential: 32-byte value from DeriveSubcredential()
//
// Spec: https://geti2p.net/spec/encryptedleaseset
func (els *EncryptedLeaseSet) DecryptInnerData(subcredential [32]byte) (*lease_set2.LeaseSet2, error) {
	log.WithFields(logger.Fields{
		"encrypted_length": len(els.encryptedInnerData),
		"published":        els.published,
	}).Debug("Decrypting EncryptedLeaseSet inner data")

	plaintext, err := decryptTwoLayers(
		els.encryptedInnerData, subcredential, els.published)
	if err != nil {
		return nil, err
	}

	return parseDecryptedLeaseSet2(plaintext)
}

// decryptTwoLayers performs the two-layer ChaCha20 decryption.
func decryptTwoLayers(data []byte, subcred [32]byte, published uint32) ([]byte, error) {
	if len(data) < ENCRYPTED_LEASESET_OUTER_SALT_SIZE+1 {
		return nil, oops.Errorf("encrypted data too short: got %d bytes", len(data))
	}

	outerSalt := data[:ENCRYPTED_LEASESET_OUTER_SALT_SIZE]
	layer1CT := data[ENCRYPTED_LEASESET_OUTER_SALT_SIZE:]
	ikm := buildLayerIKM(subcred, published)

	layer1PT, err := decryptLayer(outerSalt, ikm, "ELS2_L1K", layer1CT)
	if err != nil {
		return nil, oops.Errorf("Layer 1 decryption failed: %w", err)
	}

	return parseAndDecryptLayer2(layer1PT, ikm)
}

// decryptLayer derives a key from salt+ikm+info and decrypts ciphertext.
func decryptLayer(salt, ikm []byte, info string, ct []byte) ([]byte, error) {
	key, iv, err := deriveLayerKey(salt, ikm, info)
	if err != nil {
		return nil, err
	}
	return chacha20Crypt(key, iv, ct)
}

// parseAndDecryptLayer2 parses the Layer 1 plaintext and decrypts Layer 2.
func parseAndDecryptLayer2(layer1PT, ikm []byte) ([]byte, error) {
	if len(layer1PT) < 1 {
		return nil, oops.Errorf("Layer 1 plaintext empty")
	}
	authType := layer1PT[0]
	remaining := layer1PT[1:]

	if authType != ENCRYPTED_LEASESET_AUTH_TYPE_NONE {
		return nil, oops.Errorf(
			"per-client auth type %d not implemented (only type 0 supported)",
			authType)
	}

	if len(remaining) < ENCRYPTED_LEASESET_INNER_SALT_SIZE {
		return nil, oops.Errorf(
			"Layer 1 plaintext too short for inner salt: got %d, need %d",
			len(remaining), ENCRYPTED_LEASESET_INNER_SALT_SIZE)
	}
	innerSalt := remaining[:ENCRYPTED_LEASESET_INNER_SALT_SIZE]
	layer2CT := remaining[ENCRYPTED_LEASESET_INNER_SALT_SIZE:]

	return decryptLayer(innerSalt, ikm, "ELS2_L2K", layer2CT)
}

// EncryptInnerLeaseSet2 encrypts a LeaseSet2 using the I2P spec's two-layer
// ChaCha20 encryption scheme (no per-client auth).
//
// Encryption process:
//  1. Serialize LeaseSet2 to bytes
//  2. Generate random innerSalt, derive Layer 2 key, encrypt with ChaCha20
//  3. Assemble Layer 1 plaintext: authType(0) || innerSalt || layer2Ciphertext
//  4. Generate random outerSalt, derive Layer 1 key, encrypt with ChaCha20
//  5. Return: outerSalt || layer1Ciphertext
//
// Parameters:
//   - ls2: The LeaseSet2 to encrypt
//   - subcredential: 32-byte value from DeriveSubcredential()
//   - published: Published timestamp (seconds since epoch), must match the
//     EncryptedLeaseSet's published field
//
// Spec: https://geti2p.net/spec/encryptedleaseset
func EncryptInnerLeaseSet2(ls2 *lease_set2.LeaseSet2, subcredential [32]byte, published uint32) ([]byte, error) {
	log.WithFields(logger.Fields{
		"num_leases": len(ls2.Leases()),
		"published":  published,
	}).Debug("Encrypting LeaseSet2 (two-layer ChaCha20)")

	plaintext, err := ls2.Bytes()
	if err != nil {
		return nil, oops.Errorf("LeaseSet2 serialization failed: %w", err)
	}

	return encryptTwoLayers(plaintext, subcredential, published)
}

// encryptTwoLayers performs the two-layer ChaCha20 encryption.
func encryptTwoLayers(plaintext []byte, subcred [32]byte, published uint32) ([]byte, error) {
	ikm := buildLayerIKM(subcred, published)

	// Layer 2: innerSalt + encrypt(plaintext)
	innerSalt := make([]byte, ENCRYPTED_LEASESET_INNER_SALT_SIZE)
	if _, err := rand.Read(innerSalt); err != nil {
		return nil, oops.Errorf("inner salt generation failed: %w", err)
	}
	layer2CT, err := encryptLayer(innerSalt, ikm, "ELS2_L2K", plaintext)
	if err != nil {
		return nil, oops.Errorf("Layer 2 encryption failed: %w", err)
	}

	// Layer 1 plaintext: authType(0) || innerSalt || layer2CT
	layer1PT := assembleLayer1Plaintext(innerSalt, layer2CT)

	// Layer 1: outerSalt + encrypt(layer1PT)
	outerSalt := make([]byte, ENCRYPTED_LEASESET_OUTER_SALT_SIZE)
	if _, err := rand.Read(outerSalt); err != nil {
		return nil, oops.Errorf("outer salt generation failed: %w", err)
	}
	layer1CT, err := encryptLayer(outerSalt, ikm, "ELS2_L1K", layer1PT)
	if err != nil {
		return nil, oops.Errorf("Layer 1 encryption failed: %w", err)
	}

	result := make([]byte, 0, len(outerSalt)+len(layer1CT))
	result = append(result, outerSalt...)
	result = append(result, layer1CT...)

	log.WithField("encrypted_length", len(result)).
		Info("Successfully encrypted LeaseSet2")
	return result, nil
}

// encryptLayer derives a key from salt+ikm+info and encrypts plaintext.
func encryptLayer(salt, ikm []byte, info string, pt []byte) ([]byte, error) {
	key, iv, err := deriveLayerKey(salt, ikm, info)
	if err != nil {
		return nil, err
	}
	return chacha20Crypt(key, iv, pt)
}

// assembleLayer1Plaintext builds: authType(0) || innerSalt || layer2CT.
func assembleLayer1Plaintext(innerSalt, layer2CT []byte) []byte {
	result := make([]byte, 0, 1+len(innerSalt)+len(layer2CT))
	result = append(result, ENCRYPTED_LEASESET_AUTH_TYPE_NONE)
	result = append(result, innerSalt...)
	result = append(result, layer2CT...)
	return result
}

// parseDecryptedLeaseSet2 parses decrypted plaintext as a LeaseSet2.
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
	log.WithFields(logFields).
		Info("Successfully decrypted and parsed EncryptedLeaseSet")

	return &innerLS2, nil
}
