package encrypted_leaseset

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

// DeriveSubcredential computes the I2P subcredential for EncryptedLeaseSet
// encryption and decryption.
//
// Per the I2P spec (https://geti2p.net/spec/encryptedleaseset §473–499):
//
//	A      = destination's signing public key
//	stA    = signature type of A, 2 bytes big-endian (e.g. 0x0007 for Ed25519, 0x000b for RedDSA)
//	stA'   = signature type of the blinded key A', 2 bytes big-endian (0x000b for RedDSA)
//	keydata    = A || stA || stA'
//	credential = H("credential", keydata)
//	subcredential = H("subcredential", credential || blindedPublicKey)
//
// Parameters:
//   - destSigningPubKey: The unblinded destination signing public key bytes
//   - sigTypeA: Signature type of the unblinded key (e.g. 7 for Ed25519, 11 for RedDSA)
//   - blindedPubKey: The blinded signing public key from the EncryptedLeaseSet
//   - sigTypeBlinded: Signature type of the blinded key (always 11 for RedDSA)
//
// The subcredential binds the encryption to knowledge of the destination,
// so only clients who know the original destination can decrypt.
func DeriveSubcredential(destSigningPubKey []byte, sigTypeA uint16, blindedPubKey []byte, sigTypeBlinded uint16) [32]byte {
	credential := deriveCredential(destSigningPubKey, sigTypeA, sigTypeBlinded)
	return deriveSubcredFromCredential(credential, blindedPubKey)
}

// deriveCredential computes: SHA-256("credential" || A || stA || stA')
// where stA and stA' are the 2-byte big-endian signature type codes.
func deriveCredential(destSigningPubKey []byte, sigTypeA, sigTypeBlinded uint16) [32]byte {
	h := sha256.New()
	h.Write([]byte("credential"))
	h.Write(destSigningPubKey)
	_ = binary.Write(h, binary.BigEndian, sigTypeA)
	_ = binary.Write(h, binary.BigEndian, sigTypeBlinded)
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

// buildLayerIKM constructs the HKDF input keying material for Layer 1:
// ikm = subcredential || published (4 bytes big-endian).
func buildLayerIKM(subcredential [32]byte, published uint32) []byte {
	ikm := make([]byte, 36)
	copy(ikm[:32], subcredential[:])
	binary.BigEndian.PutUint32(ikm[32:], published)
	return ikm
}

// buildLayer2IKM constructs the HKDF input keying material for Layer 2:
// ikm = authCookie || subcredential || published (4 bytes big-endian).
//
// Per spec, when per-client authorization is disabled authCookie is the
// zero-length byte array, so the result is identical to buildLayerIKM.
func buildLayer2IKM(authCookie []byte, subcredential [32]byte, published uint32) []byte {
	ikm := make([]byte, 0, len(authCookie)+36)
	ikm = append(ikm, authCookie...)
	ikm = append(ikm, subcredential[:]...)
	var pub [4]byte
	binary.BigEndian.PutUint32(pub[:], published)
	ikm = append(ikm, pub[:]...)
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
			"HKDF key derivation failed: %w", err,
		)
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
	return els.DecryptInnerDataWithCredential(subcredential, nil)
}

// DecryptInnerDataWithCredential decrypts the encrypted inner data, optionally
// supplying a per-client credential to recover the authCookie for an
// EncryptedLeaseSet that uses per-client authorization (auth type 1 DH or 2 PSK).
//
// Pass cred == nil for auth type 0 (no per-client authorization). For per-client
// LeaseSets, cred must carry the client's X25519 private key (DH) or pre-shared
// key (PSK); see ClientCredential.
//
// Spec: https://i2p.net/en/docs/specs/encryptedleaseset
func (els *EncryptedLeaseSet) DecryptInnerDataWithCredential(subcredential [32]byte, cred *ClientCredential) (*lease_set2.LeaseSet2, error) {
	log.WithFields(logger.Fields{
		"pkg":              "encrypted_leaseset",
		"func":             "EncryptedLeaseSet.DecryptInnerDataWithCredential",
		"encrypted_length": len(els.encryptedInnerData),
		"published":        els.published,
		"has_credential":   cred != nil,
	}).Debug("Decrypting EncryptedLeaseSet inner data")

	plaintext, err := decryptTwoLayers(
		els.encryptedInnerData, subcredential, els.published, cred,
	)
	if err != nil {
		return nil, err
	}

	return parseDecryptedLeaseSet2(plaintext)
}

// decryptTwoLayers performs the two-layer ChaCha20 decryption.
func decryptTwoLayers(data []byte, subcred [32]byte, published uint32, cred *ClientCredential) ([]byte, error) {
	if len(data) < ENCRYPTED_LEASESET_OUTER_SALT_SIZE+1 {
		return nil, oops.Errorf("encrypted data too short: got %d bytes", len(data))
	}

	outerSalt := data[:ENCRYPTED_LEASESET_OUTER_SALT_SIZE]
	layer1CT := data[ENCRYPTED_LEASESET_OUTER_SALT_SIZE:]
	outerIKM := buildLayerIKM(subcred, published)

	layer1PT, err := decryptLayer(outerSalt, outerIKM, "ELS2_L1K", layer1CT)
	if err != nil {
		return nil, oops.Errorf("Layer 1 decryption failed: %w", err)
	}

	return parseAndDecryptLayer2(layer1PT, subcred, published, cred)
}

// decryptLayer derives a key from salt+ikm+info and decrypts ciphertext.
func decryptLayer(salt, ikm []byte, info string, ct []byte) ([]byte, error) {
	key, iv, err := deriveLayerKey(salt, ikm, info)
	if err != nil {
		return nil, err
	}
	return chacha20Crypt(key, iv, ct)
}

// parseAndDecryptLayer2 parses the Layer 1 plaintext, recovers the authCookie
// (for per-client auth), and decrypts Layer 2.
//
// Layer 1 plaintext layout: flag(1) || [per-client auth block] || innerCiphertext
// where innerCiphertext = innerSalt(32) || Layer2Ciphertext.
func parseAndDecryptLayer2(layer1PT []byte, subcred [32]byte, published uint32, cred *ClientCredential) ([]byte, error) {
	if len(layer1PT) < 1 {
		return nil, oops.Errorf("Layer 1 plaintext empty")
	}
	authType, err := parseAuthFlag(layer1PT[0])
	if err != nil {
		return nil, err
	}
	remaining := layer1PT[1:]

	var authCookie []byte // zero-length when no per-client auth
	if authType != ENCRYPTED_LEASESET_AUTH_TYPE_NONE {
		authCookie, remaining, err = recoverAuthCookie(authType, remaining, cred, subcred, published)
		if err != nil {
			return nil, err
		}
	}

	if len(remaining) < ENCRYPTED_LEASESET_INNER_SALT_SIZE {
		return nil, oops.Errorf(
			"Layer 1 plaintext too short for inner salt: got %d, need %d",
			len(remaining), ENCRYPTED_LEASESET_INNER_SALT_SIZE,
		)
	}
	innerSalt := remaining[:ENCRYPTED_LEASESET_INNER_SALT_SIZE]
	layer2CT := remaining[ENCRYPTED_LEASESET_INNER_SALT_SIZE:]
	innerIKM := buildLayer2IKM(authCookie, subcred, published)

	return decryptLayer(innerSalt, innerIKM, "ELS2_L2K", layer2CT)
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
	return EncryptInnerLeaseSet2WithAuth(ls2, subcredential, published, nil)
}

// EncryptInnerLeaseSet2WithAuth encrypts a LeaseSet2 using the two-layer ChaCha20
// scheme, optionally restricting decryption to authorized clients via per-client
// authorization (auth type 1 DH or 2 PSK).
//
// Pass cfg == nil for auth type 0 (no per-client authorization), which is
// equivalent to EncryptInnerLeaseSet2. When cfg is supplied, a fresh random
// authCookie is generated, encrypted to each authorized client, and folded into
// the Layer 2 key derivation so that only authorized clients can decrypt.
//
// Spec: https://i2p.net/en/docs/specs/encryptedleaseset
func EncryptInnerLeaseSet2WithAuth(ls2 *lease_set2.LeaseSet2, subcredential [32]byte, published uint32, cfg *ClientAuthConfig) ([]byte, error) {
	log.WithFields(logger.Fields{
		"pkg":        "encrypted_leaseset",
		"func":       "EncryptInnerLeaseSet2WithAuth",
		"num_leases": len(ls2.Leases()),
		"published":  published,
		"per_client": cfg != nil,
	}).Debug("Encrypting LeaseSet2 (two-layer ChaCha20)")

	plaintext, err := ls2.Bytes()
	if err != nil {
		return nil, oops.Errorf("LeaseSet2 serialization failed: %w", err)
	}

	return encryptTwoLayers(plaintext, subcredential, published, cfg)
}

// encryptTwoLayers performs the two-layer ChaCha20 encryption.
func encryptTwoLayers(plaintext []byte, subcred [32]byte, published uint32, cfg *ClientAuthConfig) ([]byte, error) {
	flagByte, authBlock, authCookie, err := buildLayer1AuthSection(cfg, subcred, published)
	if err != nil {
		return nil, err
	}

	// Layer 2: innerSalt + encrypt(plaintext), keyed with authCookie (if any).
	innerSalt := make([]byte, ENCRYPTED_LEASESET_INNER_SALT_SIZE)
	if _, err := rand.Read(innerSalt); err != nil {
		return nil, oops.Errorf("inner salt generation failed: %w", err)
	}
	layer2IKM := buildLayer2IKM(authCookie, subcred, published)
	layer2CT, err := encryptLayer(innerSalt, layer2IKM, "ELS2_L2K", plaintext)
	if err != nil {
		return nil, oops.Errorf("Layer 2 encryption failed: %w", err)
	}

	// Layer 1 plaintext: flag(1) || authBlock || innerSalt || layer2CT
	layer1PT := assembleLayer1Plaintext(flagByte, authBlock, innerSalt, layer2CT)

	// Layer 1: outerSalt + encrypt(layer1PT)
	outerSalt := make([]byte, ENCRYPTED_LEASESET_OUTER_SALT_SIZE)
	if _, err := rand.Read(outerSalt); err != nil {
		return nil, oops.Errorf("outer salt generation failed: %w", err)
	}
	outerIKM := buildLayerIKM(subcred, published)
	layer1CT, err := encryptLayer(outerSalt, outerIKM, "ELS2_L1K", layer1PT)
	if err != nil {
		return nil, oops.Errorf("Layer 1 encryption failed: %w", err)
	}

	result := make([]byte, 0, len(outerSalt)+len(layer1CT))
	result = append(result, outerSalt...)
	result = append(result, layer1CT...)

	log.WithFields(logger.Fields{"pkg": "encrypted_leaseset", "func": "encryptTwoLayers", "encrypted_length": len(result)}).
		Info("Successfully encrypted LeaseSet2")
	return result, nil
}

// buildLayer1AuthSection derives the Layer 1 flag byte, the optional per-client
// auth block, and the authCookie used to key Layer 2. When cfg is nil it returns
// flag 0, an empty block, and a zero-length authCookie (no per-client auth).
func buildLayer1AuthSection(cfg *ClientAuthConfig, subcred [32]byte, published uint32) (byte, []byte, []byte, error) {
	if cfg == nil {
		return ENCRYPTED_LEASESET_AUTH_TYPE_NONE, nil, nil, nil
	}
	if err := validateClientAuthConfig(cfg); err != nil {
		return 0, nil, nil, err
	}
	flagByte, err := authFlagByte(cfg.AuthType)
	if err != nil {
		return 0, nil, nil, err
	}
	authBlock, authCookie, err := buildClientAuthBlock(cfg, subcred, published)
	if err != nil {
		return 0, nil, nil, err
	}
	return flagByte, authBlock, authCookie[:], nil
}

// encryptLayer derives a key from salt+ikm+info and encrypts plaintext.
func encryptLayer(salt, ikm []byte, info string, pt []byte) ([]byte, error) {
	key, iv, err := deriveLayerKey(salt, ikm, info)
	if err != nil {
		return nil, err
	}
	return chacha20Crypt(key, iv, pt)
}

// assembleLayer1Plaintext builds: flag(1) || authBlock || innerSalt || layer2CT.
// authBlock is empty (nil) when per-client authorization is disabled.
func assembleLayer1Plaintext(flagByte byte, authBlock, innerSalt, layer2CT []byte) []byte {
	result := make([]byte, 0, 1+len(authBlock)+len(innerSalt)+len(layer2CT))
	result = append(result, flagByte)
	result = append(result, authBlock...)
	result = append(result, innerSalt...)
	result = append(result, layer2CT...)
	return result
}

// parseDecryptedLeaseSet2 parses decrypted plaintext as a LeaseSet2.
func parseDecryptedLeaseSet2(plaintext []byte) (*lease_set2.LeaseSet2, error) {
	innerLS2, _, err := lease_set2.ReadLeaseSet2(plaintext)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "encrypted_leaseset", "func": "parseDecryptedLeaseSet2"}).WithError(err).Error("Failed to parse decrypted data as LeaseSet2")
		return nil, oops.Errorf("invalid LeaseSet2 in decrypted data: %w", err)
	}

	logFields := logger.Fields{
		"pkg":        "encrypted_leaseset",
		"func":       "parseDecryptedLeaseSet2",
		"num_leases": len(innerLS2.Leases()),
	}
	if addr, err := innerLS2.Destination().Base32Address(); err == nil {
		logFields["destination"] = addr[:16] + "..."
	}
	log.WithFields(logFields).
		Info("Successfully decrypted and parsed EncryptedLeaseSet")

	return &innerLS2, nil
}
