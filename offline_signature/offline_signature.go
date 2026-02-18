// Package offline_signature implements the I2P OfflineSignature common data structure
// according to specification version 0.9.67.
//
// OfflineSignature provides enhanced security for I2P destinations by enabling the use
// of short-lived transient signing keys while keeping the long-term destination signing
// key offline. This structure is used in LeaseSet2Header, streaming, and I2CP protocols.
//
// Key features:
//   - Transient signing keys with expiration timestamps
//   - Offline generation for enhanced security
//   - Signature verification using destination's long-term key
//   - Complete I2P specification 0.9.67 compliance
//
// Specification: https://geti2p.net/spec/common-structures#offlinesignature
// Introduced: I2P version 0.9.38 (Proposal 123)
package offline_signature

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/signature"
)

var (
	// ErrInvalidOfflineSignatureData indicates that the provided data cannot be parsed as an OfflineSignature.
	ErrInvalidOfflineSignatureData = errors.New("invalid offline signature data")

	// ErrInsufficientData indicates that there is not enough data to parse the complete OfflineSignature.
	ErrInsufficientData = errors.New("insufficient data for offline signature")

	// ErrUnknownSignatureType indicates that the signature type is not recognized or supported.
	ErrUnknownSignatureType = errors.New("unknown or unsupported signature type")

	// ErrExpiredOfflineSignature indicates that the offline signature has passed its expiration time.
	ErrExpiredOfflineSignature = errors.New("offline signature has expired")
)

// ReadOfflineSignature parses an OfflineSignature from raw byte data according to I2P specification 0.9.67.
//
// This function extracts the expiration timestamp, transient signing public key type and data,
// and the signature created by the destination's long-term signing key. The destinationSigType
// parameter is required to determine the correct signature length.
//
// Parameters:
//   - data: Raw byte slice containing the OfflineSignature data
//   - destinationSigType: Signature type of the destination (required for signature length calculation)
//
// Returns:
//   - OfflineSignature: Parsed offline signature structure
//   - remainder: Remaining bytes after the OfflineSignature
//   - error: nil on success, error describing the parsing failure otherwise
//
// The function validates:
//   - Minimum data length requirements
//   - Known signature type for transient key
//   - Known signature type for destination
//   - Sufficient data for complete structure
//
// Example usage:
//
//	offlineSig, remainder, err := ReadOfflineSignature(data, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
//	if err != nil {
//	    log.Fatal("Failed to parse offline signature:", err)
//	}
func ReadOfflineSignature(data []byte, destinationSigType uint16) (OfflineSignature, []byte, error) {
	var offlineSig OfflineSignature

	if err := validateMinimumOfflineSignatureData(len(data)); err != nil {
		return offlineSig, data, err
	}

	expires, sigtype, rem := parseOfflineSignatureHeader(data)
	offlineSig.expires = expires
	offlineSig.sigtype = sigtype

	transientKeySize, err := validateTransientKeyType(sigtype)
	if err != nil {
		return offlineSig, data, err
	}

	if err := validateTransientKeyData(len(rem), transientKeySize); err != nil {
		return offlineSig, data, err
	}

	transientKey, rem := extractTransientPublicKey(rem, transientKeySize)
	offlineSig.transientPublicKey = transientKey

	signatureSize, err := validateDestinationSignatureType(destinationSigType)
	if err != nil {
		return offlineSig, data, err
	}

	if err := validateSignatureData(len(rem), signatureSize); err != nil {
		return offlineSig, data, err
	}

	signature, remainder := extractSignature(rem, signatureSize)
	offlineSig.signature = signature
	offlineSig.destinationSigType = destinationSigType

	return offlineSig, remainder, nil
}

// validateMinimumOfflineSignatureData validates that data has sufficient bytes for header fields.
// Returns error if data is too short for expires and sigtype fields.
func validateMinimumOfflineSignatureData(dataLen int) error {
	minSize := EXPIRES_SIZE + SIGTYPE_SIZE
	if dataLen < minSize {
		return fmt.Errorf("%w: need at least %d bytes, got %d",
			ErrInsufficientData, minSize, dataLen)
	}
	return nil
}

// parseOfflineSignatureHeader parses the expires timestamp and transient signature type from data.
// Returns expires, sigtype, and remaining data after header extraction.
func parseOfflineSignatureHeader(data []byte) (uint32, uint16, []byte) {
	expires := binary.BigEndian.Uint32(data[0:4])
	sigtype := binary.BigEndian.Uint16(data[4:6])
	return expires, sigtype, data[EXPIRES_SIZE+SIGTYPE_SIZE:]
}

// validateTransientKeyType validates the transient signature type and returns its key size.
// Returns error if the signature type is unknown or unsupported.
func validateTransientKeyType(sigtype uint16) (int, error) {
	transientKeySize := SigningPublicKeySize(sigtype)
	if transientKeySize == 0 {
		return 0, fmt.Errorf("%w: transient key type %d",
			ErrUnknownSignatureType, sigtype)
	}
	return transientKeySize, nil
}

// validateTransientKeyData validates that sufficient data exists for the transient public key.
// Returns error if insufficient data remains for the key.
func validateTransientKeyData(dataLen int, transientKeySize int) error {
	if dataLen < transientKeySize {
		return fmt.Errorf("%w: need %d bytes for transient key, got %d",
			ErrInsufficientData, transientKeySize, dataLen)
	}
	return nil
}

// extractTransientPublicKey extracts the transient public key from data.
// Returns the key bytes and remaining data after extraction.
func extractTransientPublicKey(data []byte, transientKeySize int) ([]byte, []byte) {
	transientPublicKey := make([]byte, transientKeySize)
	copy(transientPublicKey, data[:transientKeySize])
	return transientPublicKey, data[transientKeySize:]
}

// validateDestinationSignatureType validates the destination signature type and returns its signature size.
// Returns error if the signature type is unknown or unsupported.
func validateDestinationSignatureType(destinationSigType uint16) (int, error) {
	signatureSize := SignatureSize(destinationSigType)
	if signatureSize == 0 {
		return 0, fmt.Errorf("%w: destination signature type %d",
			ErrUnknownSignatureType, destinationSigType)
	}
	return signatureSize, nil
}

// validateSignatureData validates that sufficient data exists for the signature.
// Returns error if insufficient data remains for the signature.
func validateSignatureData(dataLen int, signatureSize int) error {
	if dataLen < signatureSize {
		return fmt.Errorf("%w: need %d bytes for signature, got %d",
			ErrInsufficientData, signatureSize, dataLen)
	}
	return nil
}

// extractSignature extracts the signature from data.
// Returns the signature bytes and remaining data after extraction.
func extractSignature(data []byte, signatureSize int) ([]byte, []byte) {
	signature := make([]byte, signatureSize)
	copy(signature, data[:signatureSize])
	return signature, data[signatureSize:]
}

// NewOfflineSignature creates a new OfflineSignature from raw components.
// This is a convenience constructor for creating OfflineSignature structures programmatically.
//
// Parameters:
//   - expires: Unix timestamp (seconds since epoch) when the transient key expires
//   - transientSigType: Signature type of the transient signing key
//   - transientPublicKey: Raw bytes of the transient signing public key
//   - signature: Signature by the destination's long-term key
//   - destinationSigType: Signature type of the destination (for validation)
//
// Returns:
//   - OfflineSignature: Constructed offline signature structure
//   - error: nil on success, error if parameters are invalid
func NewOfflineSignature(expires uint32, transientSigType uint16, transientPublicKey []byte,
	signature []byte, destinationSigType uint16,
) (OfflineSignature, error) {
	// Validate transient signature type
	expectedKeySize := SigningPublicKeySize(transientSigType)
	if expectedKeySize == 0 {
		return OfflineSignature{}, fmt.Errorf("%w: transient key type %d",
			ErrUnknownSignatureType, transientSigType)
	}
	if len(transientPublicKey) != expectedKeySize {
		return OfflineSignature{}, fmt.Errorf("transient public key size mismatch: expected %d, got %d",
			expectedKeySize, len(transientPublicKey))
	}

	// Validate destination signature type
	expectedSigSize := SignatureSize(destinationSigType)
	if expectedSigSize == 0 {
		return OfflineSignature{}, fmt.Errorf("%w: destination signature type %d",
			ErrUnknownSignatureType, destinationSigType)
	}
	if len(signature) != expectedSigSize {
		return OfflineSignature{}, fmt.Errorf("signature size mismatch: expected %d, got %d",
			expectedSigSize, len(signature))
	}

	// Make defensive copies of input slices to prevent caller mutation
	// from corrupting the struct's internal state, matching ReadOfflineSignature behavior.
	keyData := make([]byte, len(transientPublicKey))
	copy(keyData, transientPublicKey)
	sigData := make([]byte, len(signature))
	copy(sigData, signature)

	return OfflineSignature{
		expires:            expires,
		sigtype:            transientSigType,
		transientPublicKey: keyData,
		signature:          sigData,
		destinationSigType: destinationSigType,
	}, nil
}

// Expires returns the expiration timestamp as a uint32 (seconds since epoch).
// The timestamp rolls over in 2106.
func (o *OfflineSignature) Expires() uint32 {
	return o.expires
}

// ExpiresTime returns the expiration timestamp as a time.Time for convenience.
func (o *OfflineSignature) ExpiresTime() time.Time {
	return time.Unix(int64(o.expires), 0).UTC()
}

// TransientSigType returns the signature type of the transient signing public key.
func (o *OfflineSignature) TransientSigType() uint16 {
	return o.sigtype
}

// TransientPublicKey returns a copy of the transient signing public key bytes.
func (o *OfflineSignature) TransientPublicKey() []byte {
	keyCopy := make([]byte, len(o.transientPublicKey))
	copy(keyCopy, o.transientPublicKey)
	return keyCopy
}

// Signature returns a copy of the signature bytes created by the destination's long-term key.
func (o *OfflineSignature) Signature() []byte {
	sigCopy := make([]byte, len(o.signature))
	copy(sigCopy, o.signature)
	return sigCopy
}

// DestinationSigType returns the signature type of the destination (used for signature length).
func (o *OfflineSignature) DestinationSigType() uint16 {
	return o.destinationSigType
}

// IsExpired checks if the offline signature has passed its expiration time.
// Returns true if the current time is after the expiration timestamp.
func (o *OfflineSignature) IsExpired() bool {
	return time.Now().UTC().After(o.ExpiresTime())
}

// Bytes serializes the OfflineSignature to its wire format according to I2P specification 0.9.67.
//
// The serialized format is:
//   - 4 bytes: expires (big-endian uint32)
//   - 2 bytes: sigtype (big-endian uint16)
//   - variable: transient_public_key (length determined by sigtype)
//   - variable: signature (length determined by destination signature type)
//
// Returns the complete binary representation suitable for network transmission or storage.
func (o *OfflineSignature) Bytes() []byte {
	totalSize := EXPIRES_SIZE + SIGTYPE_SIZE + len(o.transientPublicKey) + len(o.signature)
	result := make([]byte, totalSize)

	// Write expires (4 bytes, big-endian)
	binary.BigEndian.PutUint32(result[0:4], o.expires)

	// Write sigtype (2 bytes, big-endian)
	binary.BigEndian.PutUint16(result[4:6], o.sigtype)

	// Write transient public key
	offset := EXPIRES_SIZE + SIGTYPE_SIZE
	copy(result[offset:], o.transientPublicKey)
	offset += len(o.transientPublicKey)

	// Write signature
	copy(result[offset:], o.signature)

	return result
}

// Len returns the total byte length of the serialized OfflineSignature.
func (o *OfflineSignature) Len() int {
	return EXPIRES_SIZE + SIGTYPE_SIZE + len(o.transientPublicKey) + len(o.signature)
}

// String returns a human-readable representation of the OfflineSignature for debugging.
// Includes expiration time, signature types, and data lengths.
func (o *OfflineSignature) String() string {
	expiresTime := o.ExpiresTime()
	expired := ""
	if o.IsExpired() {
		expired = " [EXPIRED]"
	}

	return fmt.Sprintf("OfflineSignature{expires: %d (%s)%s, transient_sigtype: %d, transient_key_len: %d, signature_len: %d, dest_sigtype: %d}",
		o.expires,
		expiresTime.Format(time.RFC3339),
		expired,
		o.sigtype,
		len(o.transientPublicKey),
		len(o.signature),
		o.destinationSigType,
	)
}

// ExpiresDate returns the expiration timestamp as an I2P Date (8 bytes).
// This converts the 4-byte timestamp to the 8-byte I2P Date format (milliseconds since epoch).
//
// Note: The 4-byte timestamp in OfflineSignature represents seconds, while I2P Date uses milliseconds.
// This function provides conversion for compatibility with other I2P date structures.
func (o *OfflineSignature) ExpiresDate() (*data.Date, error) {
	expiresTime := time.Unix(int64(o.expires), 0).UTC()
	return data.DateFromTime(expiresTime)
}

// ValidateStructure checks if the OfflineSignature has valid field sizes and types
// without checking whether it has expired. Use this when you need to inspect or log
// historical/expired offline signatures without treating expiration as an error.
//
// Checks performed:
//   - Signature is not nil
//   - Expiration timestamp is not zero (undefined)
//   - Transient signature type is known and supported
//   - Transient public key size matches expected size for its type
//   - Destination signature type is known and supported
//   - Signature size matches expected size for destination type
//
// Returns nil if validation passes, or a descriptive error if validation fails.
func (o *OfflineSignature) ValidateStructure() error {
	if o == nil {
		return errors.New("offline signature is nil")
	}
	if o.expires == 0 {
		return errors.New("offline signature has zero expiration timestamp")
	}
	expectedKeySize := SigningPublicKeySize(o.sigtype)
	if expectedKeySize == 0 {
		return fmt.Errorf("%w: transient key type %d",
			ErrUnknownSignatureType, o.sigtype)
	}
	if len(o.transientPublicKey) != expectedKeySize {
		return fmt.Errorf("transient public key size mismatch: expected %d bytes, got %d bytes",
			expectedKeySize, len(o.transientPublicKey))
	}
	expectedSigSize := SignatureSize(o.destinationSigType)
	if expectedSigSize == 0 {
		return fmt.Errorf("%w: destination signature type %d",
			ErrUnknownSignatureType, o.destinationSigType)
	}
	if len(o.signature) != expectedSigSize {
		return fmt.Errorf("signature size mismatch: expected %d bytes, got %d bytes",
			expectedSigSize, len(o.signature))
	}
	return nil
}

// Validate checks if the OfflineSignature is properly initialized and not expired.
// This method calls ValidateStructure() for field validation and additionally checks
// that the signature has not passed its expiration time.
//
// Returns nil if validation passes, or a descriptive error if validation fails.
func (o *OfflineSignature) Validate() error {
	if err := o.ValidateStructure(); err != nil {
		return err
	}
	if o.IsExpired() {
		return fmt.Errorf("%w: expired at %s",
			ErrExpiredOfflineSignature,
			o.ExpiresTime().Format(time.RFC3339))
	}
	return nil
}

// IsValid returns true if the OfflineSignature is properly initialized and not expired.
// This is a convenience method that wraps Validate() for boolean checks.
//
// Example usage:
//
//	if !offlineSig.IsValid() {
//	    return errors.New("offline signature is invalid or expired")
//	}
func (o *OfflineSignature) IsValid() bool {
	return o.Validate() == nil
}

// SignedData returns the byte sequence that is covered by the destination's long-term
// signing key signature. Per the I2P specification:
//
//	"Signature of expires timestamp, transient sig type, and public key,
//	 by the destination public key."
//
// The returned byte layout is: expires(4) || sigtype(2) || transient_public_key(variable).
// This is the exact message that must be signed or verified.
func (o *OfflineSignature) SignedData() []byte {
	dataLen := EXPIRES_SIZE + SIGTYPE_SIZE + len(o.transientPublicKey)
	result := make([]byte, dataLen)
	binary.BigEndian.PutUint32(result[0:4], o.expires)
	binary.BigEndian.PutUint16(result[4:6], o.sigtype)
	copy(result[EXPIRES_SIZE+SIGTYPE_SIZE:], o.transientPublicKey)
	return result
}

// VerifySignature verifies the offline signature against the destination's long-term
// signing public key. This confirms that the destination authorized the transient key.
//
// Currently supports:
//   - Ed25519 (type 7): standard Ed25519 verification via crypto/ed25519
//   - Ed25519ph (type 8): prehashed Ed25519 verification
//   - RedDSA (type 11): same verification as Ed25519 (curve is identical)
//
// Returns (true, nil) if the signature is valid, (false, nil) if it is invalid,
// or (false, error) if verification cannot be performed (unsupported type, wrong key size).
func (o *OfflineSignature) VerifySignature(destinationPublicKey []byte) (bool, error) {
	if err := o.ValidateStructure(); err != nil {
		return false, fmt.Errorf("structural validation failed: %w", err)
	}
	signedData := o.SignedData()
	return verifyWithDestinationType(o.destinationSigType, destinationPublicKey, signedData, o.signature)
}

// verifyWithDestinationType dispatches signature verification based on destination type.
func verifyWithDestinationType(destSigType uint16, pubKey, message, sig []byte) (bool, error) {
	switch destSigType {
	case signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519:
		return verifyEd25519(pubKey, message, sig)
	case signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH:
		return verifyEd25519ph(pubKey, message, sig)
	default:
		return false, fmt.Errorf("signature verification not implemented for destination type %d", destSigType)
	}
}

// verifyEd25519 performs standard Ed25519 signature verification.
func verifyEd25519(pubKey, message, sig []byte) (bool, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid Ed25519 public key size: expected %d, got %d",
			ed25519.PublicKeySize, len(pubKey))
	}
	return ed25519.Verify(ed25519.PublicKey(pubKey), message, sig), nil
}

// verifyEd25519ph performs prehashed Ed25519 (Ed25519ph) signature verification.
func verifyEd25519ph(pubKey, message, sig []byte) (bool, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid Ed25519 public key size: expected %d, got %d",
			ed25519.PublicKeySize, len(pubKey))
	}
	err := ed25519.VerifyWithOptions(
		ed25519.PublicKey(pubKey), message, sig,
		&ed25519.Options{Hash: crypto.SHA512},
	)
	return err == nil, nil
}

// CreateOfflineSignature generates a complete OfflineSignature by signing the appropriate
// data with the destination's Ed25519 private key. This function implements the spec
// recommendation that offline signatures "can, and should, be generated offline."
//
// Parameters:
//   - expires: Unix timestamp (seconds since epoch) when the transient key expires
//   - transientSigType: Signature type of the transient signing public key
//   - transientPublicKey: Raw bytes of the transient signing public key
//   - destinationPrivateKey: The destination's Ed25519 private key for signing
//   - destinationSigType: Signature type of the destination (7=Ed25519, 8=Ed25519ph, 11=RedDSA)
//
// Returns the signed OfflineSignature, or an error if parameters are invalid.
func CreateOfflineSignature(
	expires uint32,
	transientSigType uint16,
	transientPublicKey []byte,
	destinationPrivateKey ed25519.PrivateKey,
	destinationSigType uint16,
) (OfflineSignature, error) {
	if err := validateCreateParams(expires, transientSigType, transientPublicKey, destinationSigType); err != nil {
		return OfflineSignature{}, err
	}
	signedData := buildSignedData(expires, transientSigType, transientPublicKey)
	sig, err := signWithDestinationType(destinationSigType, destinationPrivateKey, signedData)
	if err != nil {
		return OfflineSignature{}, fmt.Errorf("failed to sign: %w", err)
	}
	return NewOfflineSignature(expires, transientSigType, transientPublicKey, sig, destinationSigType)
}

// validateCreateParams validates the input parameters for CreateOfflineSignature.
func validateCreateParams(expires uint32, transientSigType uint16, transientPublicKey []byte, destSigType uint16) error {
	if expires == 0 {
		return errors.New("expires must be non-zero")
	}
	expectedKeySize := SigningPublicKeySize(transientSigType)
	if expectedKeySize == 0 {
		return fmt.Errorf("%w: transient key type %d", ErrUnknownSignatureType, transientSigType)
	}
	if len(transientPublicKey) != expectedKeySize {
		return fmt.Errorf("transient public key size mismatch: expected %d, got %d",
			expectedKeySize, len(transientPublicKey))
	}
	if SignatureSize(destSigType) == 0 {
		return fmt.Errorf("%w: destination signature type %d", ErrUnknownSignatureType, destSigType)
	}
	return nil
}

// buildSignedData constructs the byte sequence to be signed: expires || sigtype || transient_public_key.
func buildSignedData(expires uint32, sigtype uint16, transientPublicKey []byte) []byte {
	dataLen := EXPIRES_SIZE + SIGTYPE_SIZE + len(transientPublicKey)
	result := make([]byte, dataLen)
	binary.BigEndian.PutUint32(result[0:4], expires)
	binary.BigEndian.PutUint16(result[4:6], sigtype)
	copy(result[EXPIRES_SIZE+SIGTYPE_SIZE:], transientPublicKey)
	return result
}

// signWithDestinationType signs the data using the appropriate algorithm for the destination type.
func signWithDestinationType(destSigType uint16, privKey ed25519.PrivateKey, message []byte) ([]byte, error) {
	switch destSigType {
	case signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519:
		return ed25519.Sign(privKey, message), nil
	case signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH:
		return privKey.Sign(rand.Reader, message, &ed25519.Options{Hash: crypto.SHA512})
	default:
		return nil, fmt.Errorf("signing not implemented for destination type %d", destSigType)
	}
}
