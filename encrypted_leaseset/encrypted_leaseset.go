// Package encrypted_leaseset implements the I2P EncryptedLeaseSet common data structure
package encrypted_leaseset

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// ReadEncryptedLeaseSet parses an EncryptedLeaseSet from its spec-compliant wire format.
//
// Wire order: sig_type(2) | blinded_public_key(var) | published(4) | expires(2) |
// flags(2) | [offline_signature] | len(2) | encrypted_data(len) | signature(var)
//
// https://geti2p.net/spec/common-structures#encryptedleaseset
func ReadEncryptedLeaseSet(data []byte) (els EncryptedLeaseSet, remainder []byte, err error) {
	log.Debug("Parsing EncryptedLeaseSet structure")

	if err = validateEncryptedLeaseSetSize(data); err != nil {
		return
	}

	remainder, err = parseAllEncryptedLeaseSetFields(&els, data)
	if err != nil {
		return
	}

	if err = els.Validate(); err != nil {
		return
	}

	logParsedEncryptedLeaseSet(&els)
	return
}

// validateEncryptedLeaseSetSize checks that the input data meets the minimum size
// requirement for an EncryptedLeaseSet.
func validateEncryptedLeaseSetSize(data []byte) error {
	if len(data) < ENCRYPTED_LEASESET_MIN_SIZE {
		return oops.Code("encrypted_leaseset_too_short").
			With("data_length", len(data)).
			With("minimum_required", ENCRYPTED_LEASESET_MIN_SIZE).
			Errorf("data too short for EncryptedLeaseSet: got %d bytes, need at least %d",
				len(data), ENCRYPTED_LEASESET_MIN_SIZE)
	}
	return nil
}

// parseAllEncryptedLeaseSetFields parses all wire-format fields in sequence:
// sig_type, blinded_public_key, header fields, offline signature, encrypted data, and signature.
func parseAllEncryptedLeaseSetFields(els *EncryptedLeaseSet, data []byte) ([]byte, error) {
	var err error

	data, err = parseSigType(els, data)
	if err != nil {
		return nil, err
	}
	data, err = parseBlindedPublicKey(els, data)
	if err != nil {
		return nil, err
	}
	data, err = parseHeaderFields(els, data)
	if err != nil {
		return nil, err
	}
	data, err = parseOfflineSignature(els, data)
	if err != nil {
		return nil, err
	}
	data, err = parseEncryptedInnerData(els, data)
	if err != nil {
		return nil, err
	}
	return parseSignatureAndFinalize(els, data)
}

// logParsedEncryptedLeaseSet logs diagnostic details after successfully parsing
// an EncryptedLeaseSet.
func logParsedEncryptedLeaseSet(els *EncryptedLeaseSet) {
	log.WithFields(logger.Fields{
		"sig_type":       els.sigType,
		"inner_length":   els.innerLength,
		"has_offline":    els.HasOfflineKeys(),
		"is_unpublished": els.IsUnpublished(),
	}).Debug("Successfully parsed EncryptedLeaseSet")
}

// parseSigType reads the 2-byte sig_type field and validates it is a known type.
func parseSigType(els *EncryptedLeaseSet, data []byte) ([]byte, error) {
	if len(data) < ENCRYPTED_LEASESET_SIGTYPE_SIZE {
		return nil, oops.Code("sigtype_too_short").
			Errorf("insufficient data for sig_type field")
	}
	els.sigType = binary.BigEndian.Uint16(data[:ENCRYPTED_LEASESET_SIGTYPE_SIZE])

	if _, ok := key_certificate.SigningKeySizes[int(els.sigType)]; !ok {
		return nil, oops.Code("unknown_sig_type").
			With("sig_type", els.sigType).
			Errorf("unknown signing key type: %d", els.sigType)
	}
	return data[ENCRYPTED_LEASESET_SIGTYPE_SIZE:], nil
}

// parseBlindedPublicKey reads the blinded public key whose length is determined by sig_type.
func parseBlindedPublicKey(els *EncryptedLeaseSet, data []byte) ([]byte, error) {
	keySize := key_certificate.SigningKeySizes[int(els.sigType)].SigningPublicKeySize
	if len(data) < keySize {
		return nil, oops.Code("key_too_short").
			With("available", len(data)).
			With("need", keySize).
			Errorf("insufficient data for blinded public key: got %d, need %d",
				len(data), keySize)
	}
	els.blindedPublicKey = make([]byte, keySize)
	copy(els.blindedPublicKey, data[:keySize])
	return data[keySize:], nil
}

// parseHeaderFields reads published(4), expires(2), flags(2) and validates reserved flags.
func parseHeaderFields(els *EncryptedLeaseSet, data []byte) ([]byte, error) {
	headerSize := ENCRYPTED_LEASESET_PUBLISHED_SIZE +
		ENCRYPTED_LEASESET_EXPIRES_SIZE +
		ENCRYPTED_LEASESET_FLAGS_SIZE
	if len(data) < headerSize {
		return nil, oops.Code("header_too_short").
			With("remaining", len(data)).
			With("need", headerSize).
			Errorf("insufficient data for header fields")
	}

	els.published = binary.BigEndian.Uint32(data[:ENCRYPTED_LEASESET_PUBLISHED_SIZE])
	data = data[ENCRYPTED_LEASESET_PUBLISHED_SIZE:]

	els.expires = binary.BigEndian.Uint16(data[:ENCRYPTED_LEASESET_EXPIRES_SIZE])
	data = data[ENCRYPTED_LEASESET_EXPIRES_SIZE:]

	els.flags = binary.BigEndian.Uint16(data[:ENCRYPTED_LEASESET_FLAGS_SIZE])
	data = data[ENCRYPTED_LEASESET_FLAGS_SIZE:]

	// Spec: "Bits 15‑2: set to 0 for compatibility with future uses."
	if els.flags&ENCRYPTED_LEASESET_RESERVED_FLAGS_MASK != 0 {
		return nil, oops.Code("reserved_flags_set").
			With("flags", els.flags).
			Errorf("reserved flag bits 15‑2 must be zero, got 0x%04x", els.flags)
	}

	log.WithFields(logger.Fields{
		"published": els.published,
		"expires":   els.expires,
		"flags":     els.flags,
	}).Debug("Parsed EncryptedLeaseSet header")

	return data, nil
}

// parseOfflineSignature parses the optional offline signature when flags bit 0 is set.
func parseOfflineSignature(els *EncryptedLeaseSet, data []byte) ([]byte, error) {
	if !els.HasOfflineKeys() {
		return data, nil
	}

	offlineSig, rem, err := offline_signature.ReadOfflineSignature(data, els.sigType)
	if err != nil {
		return nil, oops.Code("offline_sig_parse_failed").
			Wrapf(err, "failed to parse offline signature in EncryptedLeaseSet")
	}
	els.offlineSignature = &offlineSig
	log.Debug("Parsed offline signature")
	return rem, nil
}

// parseEncryptedInnerData reads inner_length(2) and encrypted_data(len).
func parseEncryptedInnerData(els *EncryptedLeaseSet, data []byte) ([]byte, error) {
	if len(data) < ENCRYPTED_LEASESET_INNER_LENGTH_SIZE {
		return nil, oops.Code("inner_length_missing").
			Errorf("insufficient data for inner length field")
	}

	els.innerLength = binary.BigEndian.Uint16(data[:ENCRYPTED_LEASESET_INNER_LENGTH_SIZE])
	data = data[ENCRYPTED_LEASESET_INNER_LENGTH_SIZE:]

	if els.innerLength == 0 {
		return nil, oops.Code("zero_inner_length").
			Errorf("inner length cannot be zero")
	}

	if len(data) < int(els.innerLength) {
		return nil, oops.Code("encrypted_data_short").
			With("available", len(data)).
			With("need", els.innerLength).
			Errorf("insufficient encrypted data: got %d, need %d",
				len(data), els.innerLength)
	}

	els.encryptedInnerData = make([]byte, els.innerLength)
	copy(els.encryptedInnerData, data[:els.innerLength])
	return data[els.innerLength:], nil
}

// parseSignatureAndFinalize reads the trailing signature.
func parseSignatureAndFinalize(els *EncryptedLeaseSet, data []byte) ([]byte, error) {
	sigType := int(els.sigType)
	if els.HasOfflineKeys() && els.offlineSignature != nil {
		sigType = int(els.offlineSignature.TransientSigType())
	}

	signature, rem, err := sig.ReadSignature(data, sigType)
	if err != nil {
		return nil, oops.Code("sig_parse_failed").
			With("sig_type", sigType).
			Wrapf(err, "failed to parse signature in EncryptedLeaseSet")
	}
	els.signature = signature
	return rem, nil
}

// ————————————————————————————————————————————————
// Accessor methods
// ————————————————————————————————————————————————

// SigType returns the signing key type identifier.
func (els *EncryptedLeaseSet) SigType() uint16 {
	return els.sigType
}

// BlindedPublicKey returns a copy of the blinded signing public key.
func (els *EncryptedLeaseSet) BlindedPublicKey() []byte {
	out := make([]byte, len(els.blindedPublicKey))
	copy(out, els.blindedPublicKey)
	return out
}

// Published returns the published timestamp (seconds since Unix epoch).
func (els *EncryptedLeaseSet) Published() uint32 {
	return els.published
}

// PublishedTime returns the published timestamp as a Go time.Time.
func (els *EncryptedLeaseSet) PublishedTime() time.Time {
	return time.Unix(int64(els.published), 0).UTC()
}

// Expires returns the expiration offset in seconds from the published timestamp.
func (els *EncryptedLeaseSet) Expires() uint16 {
	return els.expires
}

// ExpirationTime returns the absolute expiration time.
func (els *EncryptedLeaseSet) ExpirationTime() time.Time {
	return els.PublishedTime().Add(time.Duration(els.expires) * time.Second)
}

// IsExpired checks if the EncryptedLeaseSet has expired.
func (els *EncryptedLeaseSet) IsExpired() bool {
	return time.Now().After(els.ExpirationTime())
}

// Flags returns the raw flags value.
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

// OfflineSignature returns the optional offline signature structure.
func (els *EncryptedLeaseSet) OfflineSignature() *offline_signature.OfflineSignature {
	return els.offlineSignature
}

// InnerLength returns the length of the encrypted inner data.
func (els *EncryptedLeaseSet) InnerLength() uint16 {
	return els.innerLength
}

// EncryptedInnerData returns a copy of the encrypted inner data.
// Callers cannot mutate the internal state through the returned slice.
func (els *EncryptedLeaseSet) EncryptedInnerData() []byte {
	out := make([]byte, len(els.encryptedInnerData))
	copy(out, els.encryptedInnerData)
	return out
}

// Signature returns the signature over the EncryptedLeaseSet data.
func (els *EncryptedLeaseSet) Signature() sig.Signature {
	return els.signature
}

// ————————————————————————————————————————————————
// Serialization
// ————————————————————————————————————————————————

// bytesWithoutSignature serializes all fields except the trailing signature.
// Used by both Bytes() and the signing path to avoid duplicate serialization logic.
func (els *EncryptedLeaseSet) bytesWithoutSignature() ([]byte, error) {
	result := make([]byte, 0, 64+len(els.blindedPublicKey)+len(els.encryptedInnerData))

	// sig_type (2 bytes)
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, els.sigType)
	result = append(result, buf...)

	// blinded_public_key
	result = append(result, els.blindedPublicKey...)

	// published (4 bytes)
	buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, els.published)
	result = append(result, buf...)

	// expires (2 bytes)
	buf = make([]byte, 2)
	binary.BigEndian.PutUint16(buf, els.expires)
	result = append(result, buf...)

	// flags (2 bytes)
	buf = make([]byte, 2)
	binary.BigEndian.PutUint16(buf, els.flags)
	result = append(result, buf...)

	// offline signature (if present)
	if els.offlineSignature != nil {
		result = append(result, els.offlineSignature.Bytes()...)
	}

	// inner_length (2 bytes)
	buf = make([]byte, 2)
	binary.BigEndian.PutUint16(buf, els.innerLength)
	result = append(result, buf...)

	// encrypted_data
	result = append(result, els.encryptedInnerData...)

	return result, nil
}

// Bytes serializes the EncryptedLeaseSet to its spec-compliant wire format.
func (els *EncryptedLeaseSet) Bytes() ([]byte, error) {
	result, err := els.bytesWithoutSignature()
	if err != nil {
		return nil, err
	}
	result = append(result, els.signature.Bytes()...)

	log.WithFields(logger.Fields{
		"total_size":      len(result),
		"inner_length":    els.innerLength,
		"has_offline_sig": els.offlineSignature != nil,
	}).Debug("Serialized EncryptedLeaseSet to bytes")

	return result, nil
}

// ————————————————————————————————————————————————
// Validation
// ————————————————————————————————————————————————

// Validate checks internal consistency of the EncryptedLeaseSet.
func (els *EncryptedLeaseSet) Validate() error {
	if els == nil {
		return oops.Errorf("encrypted lease set is nil")
	}
	if err := validateSigTypeAndKey(els); err != nil {
		return err
	}
	if err := validateEncryptedLeaseSetFields(els); err != nil {
		return err
	}
	if err := validateEncryptedInnerDataIntegrity(els); err != nil {
		return err
	}
	return els.signature.Validate()
}

// validateSigTypeAndKey validates that the sig_type is known and the blinded public key
// matches the expected size for that type.
func validateSigTypeAndKey(els *EncryptedLeaseSet) error {
	sizes, ok := key_certificate.SigningKeySizes[int(els.sigType)]
	if !ok {
		return oops.Errorf("unknown sig_type: %d", els.sigType)
	}
	if len(els.blindedPublicKey) != sizes.SigningPublicKeySize {
		return oops.Errorf("blinded public key size %d != expected %d for sig_type %d",
			len(els.blindedPublicKey), sizes.SigningPublicKeySize, els.sigType)
	}
	return nil
}

// validateEncryptedLeaseSetFields validates the expires, reserved flags, and offline
// signature consistency of the EncryptedLeaseSet.
func validateEncryptedLeaseSetFields(els *EncryptedLeaseSet) error {
	if els.expires == 0 {
		return oops.Errorf("expires offset cannot be zero")
	}
	if els.flags&ENCRYPTED_LEASESET_RESERVED_FLAGS_MASK != 0 {
		return oops.Errorf("reserved flag bits 15‑2 must be zero")
	}
	if els.HasOfflineKeys() && els.offlineSignature == nil {
		return oops.Errorf("offline keys flag set but no offline signature present")
	}
	if !els.HasOfflineKeys() && els.offlineSignature != nil {
		return oops.Errorf("offline signature present but offline keys flag not set")
	}
	return nil
}

// validateEncryptedInnerDataIntegrity validates that the encrypted inner data is present,
// meets minimum size requirements, and matches the declared inner length.
func validateEncryptedInnerDataIntegrity(els *EncryptedLeaseSet) error {
	if len(els.encryptedInnerData) == 0 {
		return oops.Errorf("encrypted inner data cannot be empty")
	}
	if len(els.encryptedInnerData) < ENCRYPTED_LEASESET_MIN_ENCRYPTED_SIZE {
		return oops.Errorf("encrypted inner data too small: %d < minimum %d",
			len(els.encryptedInnerData), ENCRYPTED_LEASESET_MIN_ENCRYPTED_SIZE)
	}
	if els.innerLength != uint16(len(els.encryptedInnerData)) {
		return oops.Errorf("inner length mismatch: field=%d, data=%d",
			els.innerLength, len(els.encryptedInnerData))
	}
	return nil
}

// IsValid returns true if the EncryptedLeaseSet passes validation.
func (els *EncryptedLeaseSet) IsValid() bool {
	return els.Validate() == nil
}
