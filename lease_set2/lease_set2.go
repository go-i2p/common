// Package lease_set2 implements the I2P LeaseSet2 common data structure
package lease_set2

import (
	"encoding/binary"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// Destination returns the destination identity associated with this LeaseSet2.
// The destination contains the signing and encryption public keys for the service.
func (ls2 *LeaseSet2) Destination() destination.Destination {
	return ls2.destination
}

// Published returns the published timestamp as a uint32 (seconds since Unix epoch).
// This timestamp indicates when the LeaseSet2 was created/published.
func (ls2 *LeaseSet2) Published() uint32 {
	return ls2.published
}

// PublishedTime returns the published timestamp as a Go time.Time value.
// Converts the 4-byte second timestamp to time.Time in UTC timezone.
func (ls2 *LeaseSet2) PublishedTime() time.Time {
	return time.Unix(int64(ls2.published), 0).UTC()
}

// Expires returns the expiration offset in seconds from the published timestamp.
// The actual expiration time is Published() + Expires().
func (ls2 *LeaseSet2) Expires() uint16 {
	return ls2.expires
}

// ExpirationTime returns the absolute expiration time as a Go time.Time value.
// This is calculated as PublishedTime() + Expires() seconds.
func (ls2 *LeaseSet2) ExpirationTime() time.Time {
	return ls2.PublishedTime().Add(time.Duration(ls2.expires) * time.Second)
}

// IsExpired checks if the LeaseSet2 has expired based on the current time.
// Returns true if the current time is after the expiration time.
func (ls2 *LeaseSet2) IsExpired() bool {
	return time.Now().After(ls2.ExpirationTime())
}

// Flags returns the raw flags value (2 bytes).
// Use HasOfflineKeys(), IsUnpublished(), IsBlinded() for flag checking.
func (ls2 *LeaseSet2) Flags() uint16 {
	return ls2.flags
}

// HasOfflineKeys returns true if the offline signature flag is set (bit 0).
// When true, the OfflineSignature field will be populated.
func (ls2 *LeaseSet2) HasOfflineKeys() bool {
	return (ls2.flags & LEASESET2_FLAG_OFFLINE_KEYS) != 0
}

// IsUnpublished returns true if the unpublished flag is set (bit 1).
// Unpublished leasesets should not be flooded or published to the network database.
func (ls2 *LeaseSet2) IsUnpublished() bool {
	return (ls2.flags & LEASESET2_FLAG_UNPUBLISHED) != 0
}

// IsBlinded returns true if the blinded flag is set (bit 2).
// When set, this unencrypted leaseset will be blinded and encrypted when published.
// Introduced in I2P version 0.9.42.
func (ls2 *LeaseSet2) IsBlinded() bool {
	return (ls2.flags & LEASESET2_FLAG_BLINDED) != 0
}

// OfflineSignature returns the optional offline signature structure.
// Returns nil if HasOfflineKeys() is false.
func (ls2 *LeaseSet2) OfflineSignature() *offline_signature.OfflineSignature {
	return ls2.offlineSignature
}

// Options returns the mapping containing service record options.
// Options are used for DNS-SD style service discovery.
func (ls2 *LeaseSet2) Options() common.Mapping {
	return ls2.options
}

// EncryptionKeys returns the slice of encryption keys.
// Keys are in order of server preference, most-preferred first.
func (ls2 *LeaseSet2) EncryptionKeys() []EncryptionKey {
	return ls2.encryptionKeys
}

// EncryptionKeyCount returns the number of encryption keys in this LeaseSet2.
func (ls2 *LeaseSet2) EncryptionKeyCount() int {
	return len(ls2.encryptionKeys)
}

// Leases returns the slice of Lease2 structures.
func (ls2 *LeaseSet2) Leases() []lease.Lease2 {
	return ls2.leases
}

// LeaseCount returns the number of Lease2 structures in this LeaseSet2.
func (ls2 *LeaseSet2) LeaseCount() int {
	return len(ls2.leases)
}

// Signature returns the signature over the LeaseSet2 data.
// The signature is created by the destination's signing key or the transient key if offline signature is present.
func (ls2 *LeaseSet2) Signature() sig.Signature {
	return ls2.signature
}

// ReadLeaseSet2 parses a LeaseSet2 structure from the provided byte slice.
// Returns the parsed LeaseSet2, remaining bytes, and any error encountered.
//
// The parsing process:
//  1. Parse destination (387+ bytes)
//  2. Parse published timestamp (4 bytes)
//  3. Parse expires offset (2 bytes)
//  4. Parse flags (2 bytes)
//  5. If flags bit 0 set, parse offline signature (variable length)
//  6. Parse options mapping (variable length, 2+ bytes)
//  7. Parse encryption keys (1+ keys, variable length)
//  8. Parse Lease2 structures (0+ leases, 40 bytes each)
//  9. Parse signature (variable length based on signature type)
//
// Returns error if:
//   - Data is too short for minimum LeaseSet2 size
//   - Destination parsing fails
//   - Any component parsing fails
//   - Number of encryption keys or leases exceeds maximum allowed
func ReadLeaseSet2(data []byte) (ls2 LeaseSet2, remainder []byte, err error) {
	log.Debug("Parsing LeaseSet2 structure")

	// Parse destination and header fields
	data, err = parseDestinationAndHeader(&ls2, data)
	if err != nil {
		return
	}

	// Parse optional offline signature
	data, err = parseOfflineSignature(&ls2, data)
	if err != nil {
		return
	}

	// Parse options mapping
	data, err = parseOptionsMapping(&ls2, data)
	if err != nil {
		return
	}

	// Parse encryption keys
	data, err = parseEncryptionKeys(&ls2, data)
	if err != nil {
		return
	}

	// Parse Lease2 structures
	data, err = parseLeases(&ls2, data)
	if err != nil {
		return
	}

	// Parse signature and finalize
	remainder, err = parseSignatureAndFinalize(&ls2, data)
	if err != nil {
		return
	}

	return
}

// parseDestinationAndHeader validates minimum size and parses the destination and header fields.
// Returns remaining data after parsing or error if validation or parsing fails.
func parseDestinationAndHeader(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	// Validate minimum size
	if len(data) < LEASESET2_MIN_SIZE {
		err := oops.
			Code("lease_set2_too_short").
			With("data_length", len(data)).
			With("minimum_required", LEASESET2_MIN_SIZE).
			Errorf("data too short for LeaseSet2: got %d bytes, need at least %d", len(data), LEASESET2_MIN_SIZE)
		log.WithFields(logger.Fields{
			"at":          "parseDestinationAndHeader",
			"data_length": len(data),
			"min_size":    LEASESET2_MIN_SIZE,
		}).Error(err.Error())
		return nil, err
	}

	// Parse destination
	dest, rem, err := destination.ReadDestination(data)
	if err != nil {
		err = oops.
			Code("destination_parse_failed").
			Wrapf(err, "failed to parse destination in LeaseSet2")
		log.WithFields(logger.Fields{
			"at":     "parseDestinationAndHeader",
			"reason": "destination parse failed",
		}).Error(err.Error())
		return nil, err
	}
	ls2.destination = dest
	data = rem

	// Validate remaining data for header fields
	if len(data) < LEASESET2_PUBLISHED_SIZE+LEASESET2_EXPIRES_SIZE+LEASESET2_FLAGS_SIZE {
		err = oops.
			Code("header_too_short").
			With("remaining_length", len(data)).
			Errorf("insufficient data for LeaseSet2 header fields")
		log.WithFields(logger.Fields{
			"at":               "parseDestinationAndHeader",
			"remaining_length": len(data),
		}).Error(err.Error())
		return nil, err
	}

	// Parse published timestamp (4 bytes)
	ls2.published = binary.BigEndian.Uint32(data[:LEASESET2_PUBLISHED_SIZE])
	data = data[LEASESET2_PUBLISHED_SIZE:]

	// Parse expires offset (2 bytes)
	ls2.expires = binary.BigEndian.Uint16(data[:LEASESET2_EXPIRES_SIZE])
	data = data[LEASESET2_EXPIRES_SIZE:]

	// Parse flags (2 bytes)
	ls2.flags = binary.BigEndian.Uint16(data[:LEASESET2_FLAGS_SIZE])
	data = data[LEASESET2_FLAGS_SIZE:]

	log.WithFields(logger.Fields{
		"published": ls2.published,
		"expires":   ls2.expires,
		"flags":     ls2.flags,
	}).Debug("Parsed LeaseSet2 header")

	return data, nil
}

// parseOfflineSignature parses the optional offline signature if the offline keys flag is set.
// Returns remaining data after parsing or error if parsing fails.
func parseOfflineSignature(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	if !ls2.HasOfflineKeys() {
		return data, nil
	}

	// Get destination signature type for offline signature parsing
	destSigType := uint16(ls2.destination.KeyCertificate.SigningPublicKeyType())

	offlineSig, rem, err := offline_signature.ReadOfflineSignature(data, destSigType)
	if err != nil {
		err = oops.
			Code("offline_signature_parse_failed").
			Wrapf(err, "failed to parse offline signature in LeaseSet2")
		log.WithFields(logger.Fields{
			"at":     "parseOfflineSignature",
			"reason": "offline signature parse failed",
		}).Error(err.Error())
		return nil, err
	}
	ls2.offlineSignature = &offlineSig
	data = rem
	log.Debug("Parsed offline signature")

	return data, nil
}

// parseOptionsMapping parses the options mapping containing service record options.
// Returns remaining data after parsing or error if parsing fails.
func parseOptionsMapping(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	mapping, rem, errs := common.ReadMapping(data)
	if len(errs) > 0 {
		err := oops.
			Code("options_parse_failed").
			Wrapf(errs[0], "failed to parse options mapping in LeaseSet2")
		log.WithFields(logger.Fields{
			"at":     "parseOptionsMapping",
			"reason": "options mapping parse failed",
		}).Error(err.Error())
		return nil, err
	}
	ls2.options = mapping
	log.Debug("Parsed options mapping")

	return rem, nil
}

// parseEncryptionKeys parses the encryption keys from the data.
// Returns remaining data after parsing or error if validation or parsing fails.
func parseEncryptionKeys(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	if len(data) < 1 {
		err := oops.
			Code("missing_encryption_key_count").
			Errorf("insufficient data for encryption key count")
		log.WithFields(logger.Fields{
			"at": "parseEncryptionKeys",
		}).Error(err.Error())
		return nil, err
	}

	numKeys := int(data[0])
	data = data[1:]

	if numKeys < 1 || numKeys > LEASESET2_MAX_ENCRYPTION_KEYS {
		err := oops.
			Code("invalid_encryption_key_count").
			With("num_keys", numKeys).
			With("max_allowed", LEASESET2_MAX_ENCRYPTION_KEYS).
			Errorf("invalid encryption key count: %d (must be 1-%d)", numKeys, LEASESET2_MAX_ENCRYPTION_KEYS)
		log.WithFields(logger.Fields{
			"at":       "parseEncryptionKeys",
			"num_keys": numKeys,
		}).Error(err.Error())
		return nil, err
	}

	ls2.encryptionKeys = make([]EncryptionKey, numKeys)
	for i := 0; i < numKeys; i++ {
		var err error
		data, err = parseSingleEncryptionKey(ls2, i, data)
		if err != nil {
			return nil, err
		}
	}

	return data, nil
}

// parseSingleEncryptionKey parses a single encryption key at the specified index.
// Returns remaining data after parsing or error if validation or parsing fails.
func parseSingleEncryptionKey(ls2 *LeaseSet2, keyIndex int, data []byte) ([]byte, error) {
	// Validate data for key type and length fields
	if len(data) < LEASESET2_ENCRYPTION_KEY_TYPE_SIZE+LEASESET2_ENCRYPTION_KEY_LENGTH_SIZE {
		err := oops.
			Code("encryption_key_header_too_short").
			With("key_index", keyIndex).
			With("remaining_length", len(data)).
			Errorf("insufficient data for encryption key %d header", keyIndex)
		log.WithFields(logger.Fields{
			"at":        "parseSingleEncryptionKey",
			"key_index": keyIndex,
		}).Error(err.Error())
		return nil, err
	}

	// Parse key type (2 bytes)
	keyType := binary.BigEndian.Uint16(data[:LEASESET2_ENCRYPTION_KEY_TYPE_SIZE])
	data = data[LEASESET2_ENCRYPTION_KEY_TYPE_SIZE:]

	// Parse key length (2 bytes)
	keyLen := binary.BigEndian.Uint16(data[:LEASESET2_ENCRYPTION_KEY_LENGTH_SIZE])
	data = data[LEASESET2_ENCRYPTION_KEY_LENGTH_SIZE:]

	// Validate key data length
	if len(data) < int(keyLen) {
		err := oops.
			Code("encryption_key_data_too_short").
			With("key_index", keyIndex).
			With("required_length", keyLen).
			With("remaining_length", len(data)).
			Errorf("insufficient data for encryption key %d data", keyIndex)
		log.WithFields(logger.Fields{
			"at":        "parseSingleEncryptionKey",
			"key_index": keyIndex,
			"key_len":   keyLen,
		}).Error(err.Error())
		return nil, err
	}

	// Extract key data
	keyData := make([]byte, keyLen)
	copy(keyData, data[:keyLen])
	data = data[keyLen:]

	ls2.encryptionKeys[keyIndex] = EncryptionKey{
		keyType: keyType,
		keyLen:  keyLen,
		keyData: keyData,
	}

	log.WithFields(logger.Fields{
		"key_index": keyIndex,
		"key_type":  keyType,
		"key_len":   keyLen,
	}).Debug("Parsed encryption key")

	return data, nil
}

// parseLeases parses the Lease2 structures from the data.
// Returns remaining data after parsing or error if validation or parsing fails.
func parseLeases(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	if len(data) < 1 {
		err := oops.
			Code("missing_lease_count").
			Errorf("insufficient data for lease count")
		log.WithFields(logger.Fields{
			"at": "parseLeases",
		}).Error(err.Error())
		return nil, err
	}

	numLeases := int(data[0])
	data = data[1:]

	if numLeases > LEASESET2_MAX_LEASES {
		err := oops.
			Code("invalid_lease_count").
			With("num_leases", numLeases).
			With("max_allowed", LEASESET2_MAX_LEASES).
			Errorf("invalid lease count: %d (max %d)", numLeases, LEASESET2_MAX_LEASES)
		log.WithFields(logger.Fields{
			"at":          "parseLeases",
			"num_leases":  numLeases,
			"max_allowed": LEASESET2_MAX_LEASES,
		}).Error(err.Error())
		return nil, err
	}

	ls2.leases = make([]lease.Lease2, numLeases)
	for i := 0; i < numLeases; i++ {
		lease2, rem, err := lease.ReadLease2(data)
		if err != nil {
			err = oops.
				Code("lease2_parse_failed").
				With("lease_index", i).
				Wrapf(err, "failed to parse Lease2 %d", i)
			log.WithFields(logger.Fields{
				"at":          "parseLeases",
				"lease_index": i,
			}).Error(err.Error())
			return nil, err
		}
		ls2.leases[i] = lease2
		data = rem
		log.WithFields(logger.Fields{
			"lease_index": i,
		}).Debug("Parsed Lease2")
	}

	return data, nil
}

// parseSignatureAndFinalize parses the signature and logs the successful completion.
// Returns remaining data after parsing or error if parsing fails.
func parseSignatureAndFinalize(ls2 *LeaseSet2, data []byte) ([]byte, error) {
	// Determine signature type
	var sigType int
	if ls2.HasOfflineKeys() && ls2.offlineSignature != nil {
		// Use transient signature type from offline signature
		sigType = int(ls2.offlineSignature.TransientSigType())
	} else {
		// Use destination signature type
		sigType = ls2.destination.KeyCertificate.SigningPublicKeyType()
	}

	// Parse signature
	signature, rem, err := sig.ReadSignature(data, sigType)
	if err != nil {
		err = oops.
			Code("signature_parse_failed").
			Wrapf(err, "failed to parse signature in LeaseSet2")
		log.WithFields(logger.Fields{
			"at":       "parseSignatureAndFinalize",
			"sig_type": sigType,
		}).Error(err.Error())
		return nil, err
	}
	ls2.signature = signature

	log.WithFields(logger.Fields{
		"num_encryption_keys": len(ls2.encryptionKeys),
		"num_leases":          len(ls2.leases),
		"has_offline_keys":    ls2.HasOfflineKeys(),
		"is_unpublished":      ls2.IsUnpublished(),
		"is_blinded":          ls2.IsBlinded(),
	}).Debug("Successfully parsed LeaseSet2")

	return rem, nil
}
