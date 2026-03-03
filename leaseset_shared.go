// Package common provides I2P protocol common data structures and utilities.
package common

import (
	"encoding/binary"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/offline_signature"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var lsLog = logger.GetGoI2PLogger()

// SerializeLeaseSetHeader serializes the common header fields shared by
// LeaseSet2 and MetaLeaseSet: destination, published timestamp, expires
// offset, flags, optional offline signature, and options mapping.
// This eliminates duplication between serializeLeaseSet2Content and
// serializeMetaLeaseSetContent.
func SerializeLeaseSetHeader(
	dest destination.Destination,
	published uint32,
	expiresOffset uint16,
	flags uint16,
	offlineSig *offline_signature.OfflineSignature,
	options data.Mapping,
) ([]byte, error) {
	buf := make([]byte, 0)

	// Add destination
	destBytes, err := dest.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize destination: %w", err)
	}
	buf = append(buf, destBytes...)

	// Add published timestamp (4 bytes)
	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, published)
	buf = append(buf, publishedBytes...)

	// Add expires offset (2 bytes)
	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, expiresOffset)
	buf = append(buf, expiresBytes...)

	// Add flags (2 bytes)
	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, flags)
	buf = append(buf, flagsBytes...)

	// Add offline signature if present
	if offlineSig != nil {
		buf = append(buf, offlineSig.Bytes()...)
	}

	// Add options mapping — use Data() as the single consistent representation.
	if optData := options.Data(); len(optData) > 0 {
		buf = append(buf, optData...)
	} else {
		buf = append(buf, 0x00, 0x00)
	}

	return buf, nil
}

// DetermineSignatureType returns the signature type to use for lease set signing,
// consolidating the identical logic from lease_set2 and meta_leaseset packages.
func DetermineSignatureType(destSigningKeyType int, offlineSig *offline_signature.OfflineSignature) uint16 {
	if offlineSig != nil {
		return offlineSig.TransientSigType()
	}
	return uint16(destSigningKeyType)
}

// VerifyLeaseSetSignature performs the common lease set signature verification
// pattern shared across LeaseSet2, MetaLeaseSet, and LeaseSet types.
// It prepends the typeByte to the content (fullBytes minus trailing signature),
// then verifies using the provided signing public key.
func VerifyLeaseSetSignature(
	typeByte byte,
	fullBytes []byte,
	sigBytes []byte,
	signingPubKey types.SigningPublicKey,
	typeName string,
) error {
	sigLen := len(sigBytes)

	if len(fullBytes) < sigLen {
		return oops.Errorf("%s data too short for signature verification", typeName)
	}

	// Data to verify: type byte prefix + everything except the trailing signature
	contentBytes := fullBytes[:len(fullBytes)-sigLen]
	dataToVerify := make([]byte, 0, 1+len(contentBytes))
	dataToVerify = append(dataToVerify, typeByte)
	dataToVerify = append(dataToVerify, contentBytes...)

	// Create verifier and verify
	verifier, err := signingPubKey.NewVerifier()
	if err != nil {
		return oops.Errorf("failed to create verifier: %w", err)
	}

	if err := verifier.Verify(dataToVerify, sigBytes); err != nil {
		lsLog.WithError(err).Warn(typeName + " signature verification failed")
		return oops.Errorf("%s signature verification failed: %w", typeName, err)
	}

	lsLog.Debug(typeName + " signature verification succeeded")
	return nil
}

// ResolveSigningPublicKey determines which signing public key to use for
// lease set verification, consolidating the identical signingPublicKeyForVerification
// logic from lease_set2 and meta_leaseset packages.
// If offline keys are present, the transient signing public key from the
// OfflineSignature is constructed and returned. Otherwise, the Destination's
// signing public key is returned.
func ResolveSigningPublicKey(
	hasOfflineKeys bool,
	offlineSig *offline_signature.OfflineSignature,
	dest destination.Destination,
) (types.SigningPublicKey, error) {
	if hasOfflineKeys && offlineSig != nil {
		transientKeyBytes := offlineSig.TransientPublicKey()
		transientSigType := offlineSig.TransientSigType()
		spk, err := key_certificate.ConstructSigningPublicKeyByType(
			transientKeyBytes, int(transientSigType))
		if err != nil {
			return nil, oops.Errorf("failed to construct transient signing public key: %w", err)
		}
		return spk, nil
	}

	spk, err := dest.SigningPublicKey()
	if err != nil {
		return nil, oops.Errorf("failed to get signing public key from Destination: %w", err)
	}
	return spk, nil
}

// ParseOfflineSignatureField parses an optional offline signature from data
// if the offline keys flag is set, consolidating the identical parseOfflineSignature
// helper from lease_set2 and meta_leaseset packages.
func ParseOfflineSignatureField(
	hasOfflineKeys bool,
	destSigType uint16,
	inputData []byte,
	structName string,
) (*offline_signature.OfflineSignature, []byte, error) {
	if !hasOfflineKeys {
		return nil, inputData, nil
	}

	offlineSig, rem, err := offline_signature.ReadOfflineSignature(inputData, destSigType)
	if err != nil {
		err = oops.
			Code("offline_signature_parse_failed").
			Wrapf(err, "failed to parse offline signature in %s", structName)
		lsLog.WithFields(logger.Fields{
			"at":     "ParseOfflineSignatureField",
			"reason": "offline signature parse failed",
		}).Error(err.Error())
		return nil, nil, err
	}
	lsLog.Debug("Parsed offline signature")

	return &offlineSig, rem, nil
}
