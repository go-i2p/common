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
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/go-i2p/common/data"
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

	// Validate minimum length (4 bytes expires + 2 bytes sigtype)
	if len(data) < EXPIRES_SIZE+SIGTYPE_SIZE {
		return offlineSig, data, fmt.Errorf("%w: need at least %d bytes, got %d",
			ErrInsufficientData, EXPIRES_SIZE+SIGTYPE_SIZE, len(data))
	}

	// Parse expires timestamp (4 bytes, big-endian)
	offlineSig.expires = binary.BigEndian.Uint32(data[0:4])

	// Parse transient signature type (2 bytes, big-endian)
	offlineSig.sigtype = binary.BigEndian.Uint16(data[4:6])

	// Get transient public key size
	transientKeySize := SigningPublicKeySize(offlineSig.sigtype)
	if transientKeySize == 0 {
		return offlineSig, data, fmt.Errorf("%w: transient key type %d",
			ErrUnknownSignatureType, offlineSig.sigtype)
	}

	// Validate we have enough data for transient public key
	if len(data) < EXPIRES_SIZE+SIGTYPE_SIZE+transientKeySize {
		return offlineSig, data, fmt.Errorf("%w: need %d bytes for transient key, got %d",
			ErrInsufficientData, EXPIRES_SIZE+SIGTYPE_SIZE+transientKeySize, len(data))
	}

	// Extract transient public key
	offset := EXPIRES_SIZE + SIGTYPE_SIZE
	offlineSig.transientPublicKey = make([]byte, transientKeySize)
	copy(offlineSig.transientPublicKey, data[offset:offset+transientKeySize])
	offset += transientKeySize

	// Get signature size for destination's signature type
	signatureSize := SignatureSize(destinationSigType)
	if signatureSize == 0 {
		return offlineSig, data, fmt.Errorf("%w: destination signature type %d",
			ErrUnknownSignatureType, destinationSigType)
	}

	// Validate we have enough data for signature
	if len(data) < offset+signatureSize {
		return offlineSig, data, fmt.Errorf("%w: need %d bytes for signature, got %d",
			ErrInsufficientData, offset+signatureSize, len(data))
	}

	// Extract signature
	offlineSig.signature = make([]byte, signatureSize)
	copy(offlineSig.signature, data[offset:offset+signatureSize])
	offset += signatureSize

	// Store destination signature type for later validation
	offlineSig.destinationSigType = destinationSigType

	// Return the parsed OfflineSignature and remaining data
	return offlineSig, data[offset:], nil
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

	return OfflineSignature{
		expires:            expires,
		sigtype:            transientSigType,
		transientPublicKey: transientPublicKey,
		signature:          signature,
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
