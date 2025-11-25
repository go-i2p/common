// Package encrypted_leaseset implements the I2P EncryptedLeaseSet common data structure
package encrypted_leaseset

import (
	"encoding/binary"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// ReadEncryptedLeaseSet parses an EncryptedLeaseSet structure from the provided byte slice.
// Returns the parsed EncryptedLeaseSet, remaining bytes, and any error encountered.
//
// The parsing process follows I2P specification 0.9.67:
//  1. Parse blinded destination (387+ bytes)
//  2. Parse published timestamp (4 bytes)
//  3. Parse expires offset (2 bytes)
//  4. Parse flags (2 bytes)
//  5. If flags bit 0 set, parse offline signature (variable length)
//  6. Parse options mapping (2+ bytes)
//  7. Parse cookie (32 bytes)
//  8. Parse inner length (2 bytes)
//  9. Parse encrypted inner data (variable length)
//  10. Parse signature (variable length based on signature type)
//
// Returns error if:
//   - Data is too short for minimum EncryptedLeaseSet size
//   - Destination parsing fails
//   - Any component parsing fails
//   - Cookie size is invalid
//
// https://geti2p.net/spec/common-structures#encryptedleaseset
func ReadEncryptedLeaseSet(data []byte) (els EncryptedLeaseSet, remainder []byte, err error) {
	log.Debug("Parsing EncryptedLeaseSet structure")

	// Parse destination and header fields
	data, err = parseDestinationAndHeader(&els, data)
	if err != nil {
		return
	}

	// Parse optional offline signature
	data, err = parseOfflineSignature(&els, data)
	if err != nil {
		return
	}

	// Parse options mapping
	data, err = parseOptionsMapping(&els, data)
	if err != nil {
		return
	}

	// Parse cookie
	data, err = parseCookie(&els, data)
	if err != nil {
		return
	}

	// Parse inner length and encrypted data
	data, err = parseEncryptedInnerData(&els, data)
	if err != nil {
		return
	}

	// Parse signature and finalize
	remainder, err = parseSignatureAndFinalize(&els, data)
	if err != nil {
		return
	}

	return
}

// parseDestinationAndHeader validates minimum size and parses the destination and header fields.
// Returns remaining data after parsing or error if validation or parsing fails.
func parseDestinationAndHeader(els *EncryptedLeaseSet, data []byte) ([]byte, error) {
	if err := validateMinSize(len(data)); err != nil {
		return nil, err
	}

	rem, err := parseDestinationField(els, data)
	if err != nil {
		return nil, err
	}

	if err := validateHeaderDataSize(len(rem)); err != nil {
		return nil, err
	}

	rem = parseHeaderFields(els, rem)

	return rem, nil
}

// validateMinSize validates that data meets minimum EncryptedLeaseSet size requirements.
// Returns error if data is too short to contain a valid EncryptedLeaseSet.
func validateMinSize(dataLen int) error {
	if dataLen < ENCRYPTED_LEASESET_MIN_SIZE {
		err := oops.
			Code("encrypted_leaseset_too_short").
			With("data_length", dataLen).
			With("minimum_required", ENCRYPTED_LEASESET_MIN_SIZE).
			Errorf("data too short for EncryptedLeaseSet: got %d bytes, need at least %d", dataLen, ENCRYPTED_LEASESET_MIN_SIZE)
		log.WithFields(logger.Fields{
			"at":          "validateMinSize",
			"data_length": dataLen,
			"min_size":    ENCRYPTED_LEASESET_MIN_SIZE,
		}).Error(err.Error())
		return err
	}
	return nil
}

// parseDestinationField parses the blinded destination from data and updates the EncryptedLeaseSet.
// Returns remaining data after destination or error if parsing fails.
func parseDestinationField(els *EncryptedLeaseSet, data []byte) ([]byte, error) {
	dest, rem, err := destination.ReadDestination(data)
	if err != nil {
		err = oops.
			Code("destination_parse_failed").
			Wrapf(err, "failed to parse blinded destination in EncryptedLeaseSet")
		log.WithFields(logger.Fields{
			"at":     "parseDestinationField",
			"reason": "blinded destination parse failed",
		}).Error(err.Error())
		return nil, err
	}
	els.blindedDestination = dest
	return rem, nil
}

// validateHeaderDataSize validates that remaining data is sufficient for header fields.
// Returns error if insufficient data remains for published, expires, and flags fields.
func validateHeaderDataSize(dataLen int) error {
	requiredSize := ENCRYPTED_LEASESET_PUBLISHED_SIZE + ENCRYPTED_LEASESET_EXPIRES_SIZE + ENCRYPTED_LEASESET_FLAGS_SIZE
	if dataLen < requiredSize {
		err := oops.
			Code("header_too_short").
			With("remaining_length", dataLen).
			With("required_size", requiredSize).
			Errorf("insufficient data for EncryptedLeaseSet header fields")
		log.WithFields(logger.Fields{
			"at":               "validateHeaderDataSize",
			"remaining_length": dataLen,
			"required_size":    requiredSize,
		}).Error(err.Error())
		return err
	}
	return nil
}

// parseHeaderFields parses published timestamp, expires offset, and flags from data.
// Updates EncryptedLeaseSet fields and returns remaining data after header parsing.
func parseHeaderFields(els *EncryptedLeaseSet, data []byte) []byte {
	els.published = binary.BigEndian.Uint32(data[:ENCRYPTED_LEASESET_PUBLISHED_SIZE])
	data = data[ENCRYPTED_LEASESET_PUBLISHED_SIZE:]

	els.expires = binary.BigEndian.Uint16(data[:ENCRYPTED_LEASESET_EXPIRES_SIZE])
	data = data[ENCRYPTED_LEASESET_EXPIRES_SIZE:]

	els.flags = binary.BigEndian.Uint16(data[:ENCRYPTED_LEASESET_FLAGS_SIZE])
	data = data[ENCRYPTED_LEASESET_FLAGS_SIZE:]

	log.WithFields(logger.Fields{
		"published": els.published,
		"expires":   els.expires,
		"flags":     els.flags,
	}).Debug("Parsed EncryptedLeaseSet header")

	return data
}

// parseOfflineSignature parses the optional offline signature if the offline keys flag is set.
// Returns remaining data after parsing or error if parsing fails.
func parseOfflineSignature(els *EncryptedLeaseSet, data []byte) ([]byte, error) {
	if !els.HasOfflineKeys() {
		return data, nil
	}

	// Get destination signature type for offline signature parsing
	destSigType := uint16(els.blindedDestination.KeyCertificate.SigningPublicKeyType())

	offlineSig, rem, err := offline_signature.ReadOfflineSignature(data, destSigType)
	if err != nil {
		err = oops.
			Code("offline_signature_parse_failed").
			Wrapf(err, "failed to parse offline signature in EncryptedLeaseSet")
		log.WithFields(logger.Fields{
			"at":     "parseOfflineSignature",
			"reason": "offline signature parse failed",
		}).Error(err.Error())
		return nil, err
	}
	els.offlineSignature = &offlineSig
	data = rem
	log.Debug("Parsed offline signature")

	return data, nil
}

// parseOptionsMapping parses the options mapping containing service record options.
// Returns remaining data after parsing or error if parsing fails.
func parseOptionsMapping(els *EncryptedLeaseSet, data []byte) ([]byte, error) {
	mapping, rem, errs := common.ReadMapping(data)
	if len(errs) > 0 {
		err := oops.
			Code("options_parse_failed").
			Wrapf(errs[0], "failed to parse options mapping in EncryptedLeaseSet")
		log.WithFields(logger.Fields{
			"at":     "parseOptionsMapping",
			"reason": "options mapping parse failed",
		}).Error(err.Error())
		return nil, err
	}
	els.options = mapping
	log.Debug("Parsed options mapping")

	return rem, nil
}

// parseCookie parses the 32-byte cookie used for anti-replay and key derivation.
// Returns remaining data after parsing or error if insufficient data.
func parseCookie(els *EncryptedLeaseSet, data []byte) ([]byte, error) {
	if len(data) < ENCRYPTED_LEASESET_COOKIE_SIZE {
		err := oops.
			Code("cookie_too_short").
			With("remaining_length", len(data)).
			With("required_size", ENCRYPTED_LEASESET_COOKIE_SIZE).
			Errorf("insufficient data for cookie: got %d bytes, need %d", len(data), ENCRYPTED_LEASESET_COOKIE_SIZE)
		log.WithFields(logger.Fields{
			"at":               "parseCookie",
			"remaining_length": len(data),
		}).Error(err.Error())
		return nil, err
	}

	copy(els.cookie[:], data[:ENCRYPTED_LEASESET_COOKIE_SIZE])
	data = data[ENCRYPTED_LEASESET_COOKIE_SIZE:]

	log.WithFields(logger.Fields{
		"cookie_size": ENCRYPTED_LEASESET_COOKIE_SIZE,
	}).Debug("Parsed cookie")

	return data, nil
}

// parseEncryptedInnerData parses the inner length and encrypted inner data fields.
// Returns remaining data after parsing or error if insufficient data.
func parseEncryptedInnerData(els *EncryptedLeaseSet, data []byte) ([]byte, error) {
	// Parse inner length (2 bytes)
	if len(data) < ENCRYPTED_LEASESET_INNER_LENGTH_SIZE {
		err := oops.
			Code("inner_length_missing").
			With("remaining_length", len(data)).
			Errorf("insufficient data for inner length field")
		log.WithFields(logger.Fields{
			"at":               "parseEncryptedInnerData",
			"remaining_length": len(data),
		}).Error(err.Error())
		return nil, err
	}

	els.innerLength = binary.BigEndian.Uint16(data[:ENCRYPTED_LEASESET_INNER_LENGTH_SIZE])
	data = data[ENCRYPTED_LEASESET_INNER_LENGTH_SIZE:]

	// Validate inner length is reasonable (at least 1 byte, less than 64KB)
	if els.innerLength == 0 {
		err := oops.
			Code("invalid_inner_length").
			With("inner_length", els.innerLength).
			Errorf("inner length cannot be zero")
		log.WithFields(logger.Fields{
			"at": "parseEncryptedInnerData",
		}).Error(err.Error())
		return nil, err
	}

	// Parse encrypted inner data
	if len(data) < int(els.innerLength) {
		err := oops.
			Code("encrypted_data_too_short").
			With("remaining_length", len(data)).
			With("expected_length", els.innerLength).
			Errorf("insufficient data for encrypted inner data: got %d bytes, need %d", len(data), els.innerLength)
		log.WithFields(logger.Fields{
			"at":               "parseEncryptedInnerData",
			"remaining_length": len(data),
			"expected_length":  els.innerLength,
		}).Error(err.Error())
		return nil, err
	}

	els.encryptedInnerData = make([]byte, els.innerLength)
	copy(els.encryptedInnerData, data[:els.innerLength])
	data = data[els.innerLength:]

	log.WithFields(logger.Fields{
		"inner_length":       els.innerLength,
		"encrypted_data_len": len(els.encryptedInnerData),
	}).Debug("Parsed encrypted inner data")

	return data, nil
}

// parseSignatureAndFinalize parses the signature and logs the successful completion.
// Returns remaining data after parsing or error if parsing fails.
func parseSignatureAndFinalize(els *EncryptedLeaseSet, data []byte) ([]byte, error) {
	// Determine signature type
	var sigType int
	if els.HasOfflineKeys() && els.offlineSignature != nil {
		// Use transient signature type from offline signature
		sigType = int(els.offlineSignature.TransientSigType())
	} else {
		// Use blinded destination signature type
		sigType = els.blindedDestination.KeyCertificate.SigningPublicKeyType()
	}

	// Parse signature
	signature, rem, err := sig.ReadSignature(data, sigType)
	if err != nil {
		err = oops.
			Code("signature_parse_failed").
			Wrapf(err, "failed to parse signature in EncryptedLeaseSet")
		log.WithFields(logger.Fields{
			"at":       "parseSignatureAndFinalize",
			"sig_type": sigType,
		}).Error(err.Error())
		return nil, err
	}
	els.signature = signature

	log.WithFields(logger.Fields{
		"inner_length":     els.innerLength,
		"has_offline_keys": els.HasOfflineKeys(),
		"is_unpublished":   els.IsUnpublished(),
		"is_blinded":       els.IsBlinded(),
	}).Debug("Successfully parsed EncryptedLeaseSet")

	return rem, nil
}

// Accessor methods for EncryptedLeaseSet

// BlindedDestination returns the blinded destination identity associated with this EncryptedLeaseSet.
func (els *EncryptedLeaseSet) BlindedDestination() destination.Destination {
	return els.blindedDestination
}

// Published returns the published timestamp as a uint32 (seconds since Unix epoch).
func (els *EncryptedLeaseSet) Published() uint32 {
	return els.published
}

// PublishedTime returns the published timestamp as a Go time.Time value.
func (els *EncryptedLeaseSet) PublishedTime() time.Time {
	return time.Unix(int64(els.published), 0).UTC()
}

// Expires returns the expiration offset in seconds from the published timestamp.
func (els *EncryptedLeaseSet) Expires() uint16 {
	return els.expires
}

// ExpirationTime returns the absolute expiration time as a Go time.Time value.
func (els *EncryptedLeaseSet) ExpirationTime() time.Time {
	return els.PublishedTime().Add(time.Duration(els.expires) * time.Second)
}

// IsExpired checks if the EncryptedLeaseSet has expired based on the current time.
func (els *EncryptedLeaseSet) IsExpired() bool {
	return time.Now().After(els.ExpirationTime())
}

// Flags returns the raw flags value (2 bytes).
func (els *EncryptedLeaseSet) Flags() uint16 {
	return els.flags
}

// HasOfflineKeys returns true if the offline signature flag is set (bit 0).
func (els *EncryptedLeaseSet) HasOfflineKeys() bool {
	return (els.flags & ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS) != 0
}

// IsUnpublished returns true if the unpublished flag is set (bit 1).
func (els *EncryptedLeaseSet) IsUnpublished() bool {
	return (els.flags & ENCRYPTED_LEASESET_FLAG_UNPUBLISHED) != 0
}

// IsBlinded returns true if the blinded flag is set (bit 2).
// This should always be true for EncryptedLeaseSet as blinding is required.
func (els *EncryptedLeaseSet) IsBlinded() bool {
	return (els.flags & ENCRYPTED_LEASESET_FLAG_BLINDED) != 0
}

// OfflineSignature returns the optional offline signature structure.
func (els *EncryptedLeaseSet) OfflineSignature() *offline_signature.OfflineSignature {
	return els.offlineSignature
}

// Options returns the mapping containing service record options.
func (els *EncryptedLeaseSet) Options() common.Mapping {
	return els.options
}

// Cookie returns the 32-byte cookie used for anti-replay and key derivation.
func (els *EncryptedLeaseSet) Cookie() [32]byte {
	return els.cookie
}

// InnerLength returns the length of the encrypted inner data in bytes.
func (els *EncryptedLeaseSet) InnerLength() uint16 {
	return els.innerLength
}

// EncryptedInnerData returns the encrypted inner lease set data.
// This data requires decryption with the correct cookie and private key.
func (els *EncryptedLeaseSet) EncryptedInnerData() []byte {
	return els.encryptedInnerData
}

// Signature returns the signature over the EncryptedLeaseSet data.
func (els *EncryptedLeaseSet) Signature() sig.Signature {
	return els.signature
}

// Bytes serializes the EncryptedLeaseSet to its wire format representation.
// Returns the complete byte representation that can be stored in the network database.
//
// Wire format order:
//  1. Blinded destination (387+ bytes)
//  2. Published timestamp (4 bytes)
//  3. Expires offset (2 bytes)
//  4. Flags (2 bytes)
//  5. [Offline signature] (variable, if flags bit 0 set)
//  6. Options mapping (2+ bytes)
//  7. Cookie (32 bytes)
//  8. Inner length (2 bytes)
//  9. Encrypted inner data (variable)
//  10. Signature (variable, based on signature type)
//
// The signature must be generated over all preceding data prepended with
// the DatabaseStore type byte (0x05 for EncryptedLeaseSet).
func (els *EncryptedLeaseSet) Bytes() ([]byte, error) {
	result := make([]byte, 0)

	// Add blinded destination
	result = append(result, els.blindedDestination.KeysAndCert.Bytes()...)

	// Add published timestamp (4 bytes)
	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, els.published)
	result = append(result, publishedBytes...)

	// Add expires offset (2 bytes)
	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, els.expires)
	result = append(result, expiresBytes...)

	// Add flags (2 bytes)
	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, els.flags)
	result = append(result, flagsBytes...)

	// Add offline signature if present
	if els.offlineSignature != nil {
		result = append(result, els.offlineSignature.Bytes()...)
	}

	// Add options mapping
	if len(els.options.Values()) > 0 {
		result = append(result, els.options.Data()...)
	} else {
		// Empty mapping (2 bytes of zero)
		result = append(result, 0x00, 0x00)
	}

	// Add cookie (32 bytes)
	result = append(result, els.cookie[:]...)

	// Add inner length (2 bytes)
	innerLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(innerLengthBytes, els.innerLength)
	result = append(result, innerLengthBytes...)

	// Add encrypted inner data
	result = append(result, els.encryptedInnerData...)

	// Add signature
	result = append(result, els.signature.Bytes()...)

	log.WithFields(logger.Fields{
		"total_size":       len(result),
		"destination_size": len(els.blindedDestination.KeysAndCert.Bytes()),
		"inner_length":     els.innerLength,
		"has_offline_sig":  els.offlineSignature != nil,
		"options_count":    len(els.options.Values()),
	}).Debug("Serialized EncryptedLeaseSet to bytes")

	return result, nil
}
