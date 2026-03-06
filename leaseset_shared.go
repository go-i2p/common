// Package common provides I2P protocol common data structures and utilities.
package common

import (
	"crypto/ed25519"
	"encoding/binary"
	"strings"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/ed25519ph"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/red25519"
	"github.com/samber/oops"
)

// LeaseSetHeaderFieldsSize is the combined size of the published (4),
// expires (2), and flags (2) header fields shared by LeaseSet2 and MetaLeaseSet.
const LeaseSetHeaderFieldsSize = 8

// LeaseSetFlagOfflineKeys is bit 0 of the flags field, indicating that an
// offline signature is present. This constant is shared by LeaseSet2 and MetaLeaseSet.
const LeaseSetFlagOfflineKeys = 1 << 0

// LeaseSetCommonFields holds the parsed header fields that are structurally
// identical between LeaseSet2 and MetaLeaseSet wire formats.
type LeaseSetCommonFields struct {
	Destination      destination.Destination
	Published        uint32
	Expires          uint16
	Flags            uint16
	OfflineSignature *offline_signature.OfflineSignature
	Options          data.Mapping
}

// LeaseSetFieldApplier is implemented by lease set types that can receive
// parsed common header fields, eliminating duplicated field assignment code
// between LeaseSet2 and MetaLeaseSet.
type LeaseSetFieldApplier interface {
	ApplyCommonFields(fields LeaseSetCommonFields)
}

// ParseAndApplyCommonPrefix parses the common wire-format prefix shared by
// LeaseSet2 and MetaLeaseSet and applies the resulting fields to the target
// structure via the LeaseSetFieldApplier interface. This consolidates the
// duplicated parse-then-assign pattern from both ReadLeaseSet2 and
// ReadMetaLeaseSet into a single call.
func ParseAndApplyCommonPrefix(
	target LeaseSetFieldApplier, inputData []byte, minSize int, structName string,
) (remainder []byte, err error) {
	var fields LeaseSetCommonFields
	fields, remainder, err = ParseLeaseSetCommonPrefix(inputData, minSize, structName)
	if err != nil {
		return remainder, err
	}
	target.ApplyCommonFields(fields)
	return remainder, err
}

var lsLog = logger.GetGoI2PLogger()

// ParseLeaseSetCommonPrefix parses the common wire-format prefix shared by
// LeaseSet2 and MetaLeaseSet: destination, published, expires, flags, optional
// offline signature, and options mapping. This consolidates the identical
// parseDestinationAndHeader + parseOfflineSignature + parseOptionsMapping
// call sequence from both packages into a single function.
func ParseLeaseSetCommonPrefix(
	inputData []byte, minSize int, structName string,
) (fields LeaseSetCommonFields, remainder []byte, err error) {
	if err = ValidateMinDataSize(len(inputData), minSize, structName); err != nil {
		return fields, remainder, err
	}

	fields.Destination, remainder, err = ParseDestinationFromData(inputData, structName)
	if err != nil {
		return fields, remainder, err
	}

	if err = ValidateLeaseSetHeaderSize(len(remainder), structName); err != nil {
		return fields, remainder, err
	}

	fields.Published, fields.Expires, fields.Flags, remainder = ParseLeaseSetHeaderFields(remainder)

	hasOfflineKeys := (fields.Flags & LeaseSetFlagOfflineKeys) != 0
	destSigType := uint16(fields.Destination.KeyCertificate.SigningPublicKeyType())

	fields.OfflineSignature, remainder, err = ParseOfflineSignatureField(
		hasOfflineKeys, destSigType, remainder, structName,
	)
	if err != nil {
		return fields, remainder, err
	}

	fields.Options, remainder, err = ParseEmbeddedMapping(remainder, structName)
	return fields, remainder, err
}

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
	buf = AppendBigEndianUint32(buf, published)

	// Add expires offset (2 bytes)
	buf = AppendBigEndianUint16(buf, expiresOffset)

	// Add flags (2 bytes)
	buf = AppendBigEndianUint16(buf, flags)

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

	return VerifySignatureData(dataToVerify, sigBytes, signingPubKey, typeName)
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

// VerifySignatureData verifies a cryptographic signature against already-prepared
// data using the provided signing public key. This is the common "create verifier
// → verify → log" tail shared across all lease set Verify() methods.
func VerifySignatureData(
	dataToVerify []byte,
	sigBytes []byte,
	signingPubKey types.SigningPublicKey,
	typeName string,
) error {
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

// ExtractEd25519PrivateKey extracts an ed25519.PrivateKey from the signing key
// interface, consolidating the identical extractEd25519PrivateKey/extractPrivateKey
// helpers from lease_set2 and meta_leaseset packages.
func ExtractEd25519PrivateKey(signingKey interface{}) (ed25519.PrivateKey, error) {
	switch key := signingKey.(type) {
	case ed25519.PrivateKey:
		return key, nil
	case []byte:
		if len(key) != ed25519.PrivateKeySize {
			return nil, oops.Errorf("invalid signing key length: got %d, expected %d", len(key), ed25519.PrivateKeySize)
		}
		return ed25519.PrivateKey(key), nil
	case nil:
		return nil, oops.Errorf("signing key is nil")
	default:
		return nil, oops.Errorf("unsupported signing key type: %T (expected ed25519.PrivateKey)", signingKey)
	}
}

// CreateLeaseSetSignature validates the signature type, delegates signing to the
// provided signFn, and wraps the result in a Signature object. This consolidates
// the identical createLeaseSet2Signature/createMetaLeaseSetSignature wrappers.
func CreateLeaseSetSignature(
	signingKey interface{},
	data []byte,
	sigType uint16,
	signFn func(interface{}, []byte, uint16) ([]byte, error),
) (sig.Signature, error) {
	sigSize := offline_signature.SignatureSize(sigType)
	if sigSize == 0 {
		return sig.Signature{}, oops.
			Code("unknown_signature_type").
			With("signature_type", sigType).
			Errorf("unknown or unsupported signature type: %d", sigType)
	}

	signatureBytes, err := signFn(signingKey, data, sigType)
	if err != nil {
		return sig.Signature{}, err
	}

	signature, err := sig.NewSignatureFromBytes(signatureBytes, int(sigType))
	if err != nil {
		return sig.Signature{}, oops.Errorf("failed to create signature: %w", err)
	}

	return signature, nil
}

// SignLeaseSetData performs the actual cryptographic signing operation,
// dispatching to Ed25519, RedDSA, or Ed25519ph based on the sigType.
// This consolidates the identical signLeaseSet2Data and signMetaLeaseSetData.
func SignLeaseSetData(signingKey interface{}, data []byte, sigType uint16) ([]byte, error) {
	privKey, err := ExtractEd25519PrivateKey(signingKey)
	if err != nil {
		return nil, err
	}

	switch sigType {
	case uint16(sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519):
		return ed25519.Sign(privKey, data), nil
	case uint16(sig.SIGNATURE_TYPE_REDDSA_SHA512_ED25519):
		return red25519.Sign(red25519.PrivateKey(privKey), data), nil
	case uint16(sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH):
		return signEd25519ph(privKey, data)
	default:
		return nil, oops.Errorf("signing not implemented for signature type %d (modern crypto only: Ed25519, Ed25519ph, RedDSA)", sigType)
	}
}

// signEd25519ph performs Ed25519ph (pre-hashed) signing using the
// go-i2p/crypto/ed25519ph package.
func signEd25519ph(privKey ed25519.PrivateKey, data []byte) ([]byte, error) {
	pk, err := ed25519ph.NewEd25519phPrivateKey([]byte(privKey))
	if err != nil {
		return nil, oops.Errorf("invalid Ed25519ph private key: %w", err)
	}
	signer, err := pk.NewSigner()
	if err != nil {
		return nil, oops.Errorf("failed to create Ed25519ph signer: %w", err)
	}
	return signer.Sign(data)
}

// PrependLeaseSetTypeByte prepends a DatabaseStore type byte to serialized
// lease set content, consolidating the identical pattern from
// serializeLeaseSet2ForSigning and serializeMetaLeaseSetForSigning.
func PrependLeaseSetTypeByte(typeByte byte, content []byte) []byte {
	data := make([]byte, 0, 1+len(content))
	data = append(data, typeByte)
	data = append(data, content...)
	return data
}

// AppendBigEndianUint16 appends a big-endian encoded uint16 to buf,
// consolidating the repeated make-encode-append pattern used across
// multiple lease set serialization functions.
func AppendBigEndianUint16(buf []byte, val uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, val)
	return append(buf, b...)
}

// AppendBigEndianUint32 appends a big-endian encoded uint32 to buf,
// consolidating the repeated make-encode-append pattern used across
// multiple lease set serialization functions.
func AppendBigEndianUint32(buf []byte, val uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, val)
	return append(buf, b...)
}

// ValidateMinDataSize validates that dataLen meets a minimum size requirement,
// consolidating the identical validateMinSize and validateLeaseSet2MinSize
// functions from meta_leaseset and lease_set2 packages.
func ValidateMinDataSize(dataLen, minSize int, structName string) error {
	if dataLen < minSize {
		err := oops.
			Code(strings.ToLower(strings.ReplaceAll(structName, " ", "_"))+"_too_short").
			With("data_length", dataLen).
			With("minimum_required", minSize).
			Errorf("data too short for %s: got %d bytes, need at least %d", structName, dataLen, minSize)
		lsLog.WithFields(logger.Fields{
			"at":          "ValidateMinDataSize",
			"data_length": dataLen,
			"min_size":    minSize,
		}).Error(err.Error())
		return err
	}
	return nil
}

// ValidateLeaseSetHeaderSize validates that remaining data is sufficient for
// the common header fields (published, expires, flags), consolidating the
// identical validateHeaderDataSize functions from lease_set2 and meta_leaseset.
func ValidateLeaseSetHeaderSize(dataLen int, structName string) error {
	if dataLen < LeaseSetHeaderFieldsSize {
		err := oops.
			Code("header_too_short").
			With("remaining_length", dataLen).
			With("required_size", LeaseSetHeaderFieldsSize).
			Errorf("insufficient data for %s header fields", structName)
		lsLog.WithFields(logger.Fields{
			"at":               "ValidateLeaseSetHeaderSize",
			"remaining_length": dataLen,
			"required_size":    LeaseSetHeaderFieldsSize,
		}).Error(err.Error())
		return err
	}
	return nil
}

// ParseDestinationFromData parses a destination from data, consolidating the
// identical parseDestinationField functions from lease_set2 and meta_leaseset.
func ParseDestinationFromData(inputData []byte, structName string) (destination.Destination, []byte, error) {
	dest, rem, err := destination.ReadDestination(inputData)
	if err != nil {
		err = oops.
			Code("destination_parse_failed").
			Wrapf(err, "failed to parse destination in %s", structName)
		lsLog.WithFields(logger.Fields{
			"at":     "ParseDestinationFromData",
			"reason": "destination parse failed",
		}).Error(err.Error())
		return destination.Destination{}, nil, err
	}
	return dest, rem, nil
}

// ParseLeaseSetHeaderFields parses the published timestamp (4 bytes), expires
// offset (2 bytes), and flags (2 bytes) from data, consolidating the identical
// parseHeaderFields logic from lease_set2 and meta_leaseset packages.
func ParseLeaseSetHeaderFields(inputData []byte) (published uint32, expires, flags uint16, remainder []byte) {
	published = binary.BigEndian.Uint32(inputData[:4])
	inputData = inputData[4:]
	expires = binary.BigEndian.Uint16(inputData[:2])
	inputData = inputData[2:]
	flags = binary.BigEndian.Uint16(inputData[:2])
	inputData = inputData[2:]
	remainder = inputData
	return published, expires, flags, remainder
}

// ParseEmbeddedMapping parses an options mapping from data, filtering the
// expected "data exists beyond length" warning that occurs when a mapping
// is embedded in a larger structure. This consolidates the identical
// parseOptionsMapping functions from lease_set2 and meta_leaseset packages.
func ParseEmbeddedMapping(inputData []byte, structName string) (data.Mapping, []byte, error) {
	mapping, rem, errs := data.ReadMapping(inputData)
	if len(errs) > 0 {
		var fatal []error
		for _, e := range errs {
			if strings.Contains(e.Error(), "data exists beyond length of mapping") {
				lsLog.Debug("options mapping: ignoring 'data beyond length' warning (expected in embedded context)")
				continue
			}
			fatal = append(fatal, e)
		}
		if len(fatal) > 0 {
			err := oops.
				Code("options_parse_failed").
				Wrapf(fatal[0], "failed to parse options mapping in %s", structName)
			lsLog.WithFields(logger.Fields{
				"at":     "ParseEmbeddedMapping",
				"reason": "options mapping parse failed",
			}).Error(err.Error())
			return data.Mapping{}, nil, err
		}
	}
	lsLog.Debug("Parsed options mapping")
	return mapping, rem, nil
}

// ParseLeaseSetSignature determines the signature type and parses the trailing
// signature from data, consolidating the identical parseSignatureAndFinalize
// functions from lease_set2, meta_leaseset, and encrypted_leaseset packages.
func ParseLeaseSetSignature(
	inputData []byte,
	defaultSigType int,
	hasOfflineKeys bool,
	offlineSig *offline_signature.OfflineSignature,
	structName string,
) (sig.Signature, []byte, error) {
	sigType := defaultSigType
	if hasOfflineKeys && offlineSig != nil {
		sigType = int(offlineSig.TransientSigType())
	}

	signature, rem, err := sig.ReadSignature(inputData, sigType)
	if err != nil {
		err = oops.
			Code("signature_parse_failed").
			With("sig_type", sigType).
			Wrapf(err, "failed to parse signature in %s", structName)
		lsLog.WithFields(logger.Fields{
			"at":       "ParseLeaseSetSignature",
			"sig_type": sigType,
		}).Error(err.Error())
		return sig.Signature{}, nil, err
	}
	return signature, rem, nil
}
