package encrypted_leaseset

import (
	"crypto/ed25519"
	"crypto/sha512"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
	goi2ped25519 "github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// NewEncryptedLeaseSet creates a new EncryptedLeaseSet with the provided parameters.
//
// This constructor creates a properly signed EncryptedLeaseSet following I2P specification 0.9.67.
// The blinded destination should be created using CreateBlindedDestination(), and the encrypted
// inner data should be created using EncryptInnerLeaseSet2().
//
// Parameters:
//   - blindedDest: Blinded destination (derived from original via CreateBlindedDestination)
//   - published: Published timestamp in seconds since Unix epoch
//   - expiresOffset: Expiration offset in seconds from published (max 65535)
//   - flags: Flags field (bit 0=offline keys, bit 1=unpublished, bit 2=blinded)
//   - offlineSig: Optional offline signature (required if flags bit 0 is set)
//   - options: Options mapping for service discovery (can be empty)
//   - cookie: 32-byte cookie for key derivation and anti-replay
//   - encryptedInnerData: Encrypted LeaseSet2 data (from EncryptInnerLeaseSet2)
//   - signingKey: Private signing key (Ed25519 [64]byte or compatible type)
//
// Returns the constructed EncryptedLeaseSet or error if:
//   - Validation fails (invalid destination, expires offset, flags, etc.)
//   - Signing fails
//
// Example:
//
//	blindedDest, _ := CreateBlindedDestination(origDest, secret, time.Now())
//	encryptedData, _ := EncryptInnerLeaseSet2(ls2, cookie, recipientPubKey)
//	els, err := NewEncryptedLeaseSet(
//	    blindedDest,
//	    uint32(time.Now().Unix()),
//	    600,  // 10 minutes
//	    ENCRYPTED_LEASESET_FLAG_BLINDED,
//	    nil,  // no offline signature
//	    data.Mapping{},
//	    cookie,
//	    encryptedData,
//	    blindedPrivateKey,
//	)
//
// https://geti2p.net/spec/common-structures#encryptedleaseset
func NewEncryptedLeaseSet(
	blindedDest destination.Destination,
	published uint32,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	options common.Mapping,
	cookie [32]byte,
	encryptedInnerData []byte,
	signingKey interface{},
) (*EncryptedLeaseSet, error) {
	log.Debug("Creating new EncryptedLeaseSet")

	// Validate inputs
	if err := validateEncryptedLeaseSetInputs(blindedDest, expiresOffset, flags, offlineSig, encryptedInnerData); err != nil {
		return nil, err
	}

	// Calculate inner length
	innerLength := uint16(len(encryptedInnerData))

	// Construct the EncryptedLeaseSet data for signing
	dataToSign, err := serializeEncryptedLeaseSetForSigning(
		blindedDest, published, expiresOffset, flags, offlineSig, options, cookie, innerLength, encryptedInnerData,
	)
	if err != nil {
		return nil, err
	}

	// Determine signature type and sign the data
	sigType := determineEncryptedLeaseSetSignatureType(blindedDest, offlineSig)
	signature, err := createEncryptedLeaseSetSignature(signingKey, dataToSign, sigType)
	if err != nil {
		return nil, err
	}

	// Assemble the final EncryptedLeaseSet structure
	els := EncryptedLeaseSet{
		blindedDestination: blindedDest,
		published:          published,
		expires:            expiresOffset,
		flags:              flags,
		offlineSignature:   offlineSig,
		options:            options,
		cookie:             cookie,
		innerLength:        innerLength,
		encryptedInnerData: encryptedInnerData,
		signature:          signature,
	}

	log.WithFields(logger.Fields{
		"inner_length":     innerLength,
		"has_offline_keys": els.HasOfflineKeys(),
		"is_blinded":       els.IsBlinded(),
		"published":        published,
		"expires_offset":   expiresOffset,
	}).Debug("Successfully created EncryptedLeaseSet")

	return &els, nil
}

// validateEncryptedLeaseSetInputs validates all input parameters for EncryptedLeaseSet creation.
func validateEncryptedLeaseSetInputs(
	blindedDest destination.Destination,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	encryptedInnerData []byte,
) error {
	// Validate blinded destination size (minimum 387 bytes per I2P spec)
	destBytes, err := blindedDest.Bytes()
	if err != nil {
		return oops.Errorf("failed to serialize blinded destination: %w", err)
	}
	if len(destBytes) < ENCRYPTED_LEASESET_MIN_DESTINATION_SIZE {
		return oops.
			Code("invalid_destination_size").
			With("size", len(destBytes)).
			With("minimum", ENCRYPTED_LEASESET_MIN_DESTINATION_SIZE).
			Errorf("blinded destination size must be at least %d bytes", ENCRYPTED_LEASESET_MIN_DESTINATION_SIZE)
	}

	// Validate expiration offset
	if expiresOffset == 0 {
		return oops.
			Code("invalid_expires_offset").
			Errorf("expires offset cannot be zero")
	}
	if expiresOffset > ENCRYPTED_LEASESET_MAX_EXPIRES_OFFSET {
		return oops.
			Code("invalid_expires_offset").
			With("max_allowed", ENCRYPTED_LEASESET_MAX_EXPIRES_OFFSET).
			Errorf("expires offset %d exceeds maximum %d", expiresOffset, ENCRYPTED_LEASESET_MAX_EXPIRES_OFFSET)
	}

	// Validate offline signature flag consistency
	if (flags&ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS) != 0 && offlineSig == nil {
		return oops.
			Code("missing_offline_signature").
			Errorf("OFFLINE_KEYS flag set but no offline signature provided")
	}
	if (flags&ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS) == 0 && offlineSig != nil {
		return oops.
			Code("unexpected_offline_signature").
			Errorf("offline signature provided but OFFLINE_KEYS flag not set")
	}

	// Validate encrypted inner data
	if len(encryptedInnerData) == 0 {
		return oops.
			Code("empty_encrypted_data").
			Errorf("encrypted inner data cannot be empty")
	}

	// Minimum encrypted data size: ephemeral key (32) + nonce (12) + ciphertext (1+) + tag (16)
	minEncryptedSize := 32 + 12 + 1 + 16
	if len(encryptedInnerData) < minEncryptedSize {
		return oops.
			Code("encrypted_data_too_short").
			With("size", len(encryptedInnerData)).
			With("minimum", minEncryptedSize).
			Errorf("encrypted inner data size %d is too small (minimum %d)", len(encryptedInnerData), minEncryptedSize)
	}

	return nil
}

// serializeEncryptedLeaseSetForSigning serializes the EncryptedLeaseSet data that needs to be signed.
// This includes everything except the signature itself.
func serializeEncryptedLeaseSetForSigning(
	blindedDest destination.Destination,
	published uint32,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	options common.Mapping,
	cookie [32]byte,
	innerLength uint16,
	encryptedInnerData []byte,
) ([]byte, error) {
	result := make([]byte, 0)

	// Add blinded destination
	destBytes, err := blindedDest.KeysAndCert.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize blinded destination: %w", err)
	}
	result = append(result, destBytes...)

	// Add published timestamp (4 bytes)
	publishedBytes := make([]byte, 4)
	publishedBytes[0] = byte(published >> 24)
	publishedBytes[1] = byte(published >> 16)
	publishedBytes[2] = byte(published >> 8)
	publishedBytes[3] = byte(published)
	result = append(result, publishedBytes...)

	// Add expires offset (2 bytes)
	expiresBytes := make([]byte, 2)
	expiresBytes[0] = byte(expiresOffset >> 8)
	expiresBytes[1] = byte(expiresOffset)
	result = append(result, expiresBytes...)

	// Add flags (2 bytes)
	flagsBytes := make([]byte, 2)
	flagsBytes[0] = byte(flags >> 8)
	flagsBytes[1] = byte(flags)
	result = append(result, flagsBytes...)

	// Add offline signature if present
	if offlineSig != nil {
		result = append(result, offlineSig.Bytes()...)
	}

	// Add options mapping
	if len(options.Values()) > 0 {
		result = append(result, options.Data()...)
	} else {
		// Empty mapping (2 bytes of zero)
		result = append(result, 0x00, 0x00)
	}

	// Add cookie (32 bytes)
	result = append(result, cookie[:]...)

	// Add inner length (2 bytes)
	innerLengthBytes := make([]byte, 2)
	innerLengthBytes[0] = byte(innerLength >> 8)
	innerLengthBytes[1] = byte(innerLength)
	result = append(result, innerLengthBytes...)

	// Add encrypted inner data
	result = append(result, encryptedInnerData...)

	return result, nil
}

// determineEncryptedLeaseSetSignatureType determines the signature type for an EncryptedLeaseSet.
// If offline signature is present, uses transient key type; otherwise uses blinded destination's signing key type.
func determineEncryptedLeaseSetSignatureType(blindedDest destination.Destination, offlineSig *offline_signature.OfflineSignature) uint16 {
	if offlineSig != nil {
		return offlineSig.TransientSigType()
	}
	return uint16(blindedDest.KeyCertificate.SigningPublicKeyType())
}

// createEncryptedLeaseSetSignature creates a signature over the provided data using the signing key.
// Supports Ed25519 signing keys (most common for blinded destinations).
func createEncryptedLeaseSetSignature(signingKey interface{}, data []byte, sigType uint16) (sig.Signature, error) {
	// Hash data with SHA-512 before signing (I2P convention)
	h := sha512.Sum512(data)

	switch key := signingKey.(type) {
	case [64]byte:
		// Ed25519 private key - use standard crypto/ed25519
		signatureBytes := ed25519.Sign(key[:], h[:])
		return sig.NewSignatureFromBytes(signatureBytes, int(sigType)), nil

	case *goi2ped25519.Ed25519PrivateKey:
		// Direct Ed25519 private key type from go-i2p/crypto
		signatureBytes := ed25519.Sign(key.Bytes(), h[:])
		return sig.NewSignatureFromBytes(signatureBytes, int(sigType)), nil

	case []byte:
		// Try to interpret as Ed25519 private key (64 bytes)
		if len(key) == 64 {
			signatureBytes := ed25519.Sign(key, h[:])
			return sig.NewSignatureFromBytes(signatureBytes, int(sigType)), nil
		}
		return sig.Signature{}, oops.
			Code("invalid_key_length").
			With("length", len(key)).
			Errorf("byte slice signing key must be 64 bytes for Ed25519, got %d", len(key))

	default:
		return sig.Signature{}, oops.
			Code("unsupported_key_type").
			With("type", signingKey).
			Errorf("unsupported signing key type: %T (expected [64]byte, *Ed25519PrivateKey, or []byte for Ed25519)", signingKey)
	}
}
