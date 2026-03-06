// Package lease_set implements the I2P LeaseSet methods and constructor
package lease_set

import (
	"bytes"
	"crypto/sha256"
	"time"

	rootcommon "github.com/go-i2p/common"
	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	sig "github.com/go-i2p/common/signature"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"
)

var log = logger.GetGoI2PLogger()

// Validate performs structural validation of the LeaseSet.
// It checks that all fields are present, correctly sized, and internally consistent.
// It does NOT verify the cryptographic signature (use [LeaseSet.Verify] for that)
// or check temporal validity of individual leases (e.g., expiration).
// Returns an error if the lease set is nil or has invalid field values.
func (ls *LeaseSet) Validate() error {
	if ls == nil {
		return oops.Errorf("lease set is nil")
	}
	if err := validateLeaseSetCounts(ls); err != nil {
		return err
	}
	if err := validateLeaseSetKeys(ls); err != nil {
		return err
	}
	return validateLeaseSetSignature(ls)
}

// validateLeaseSetCounts validates that the lease count is within bounds and matches
// the actual number of leases.
func validateLeaseSetCounts(ls *LeaseSet) error {
	if ls.leaseCount > LEASE_SET_MAX_LEASES {
		return oops.Errorf("lease set cannot have more than 16 leases")
	}
	if len(ls.leases) != ls.leaseCount {
		return oops.Errorf("lease count mismatch: count field is %d but have %d leases",
			ls.leaseCount, len(ls.leases))
	}
	return nil
}

// validateLeaseSetKeys validates that the encryption key and signing key are present,
// have correct sizes, and are of the correct types for LeaseSet v1.
func validateLeaseSetKeys(ls *LeaseSet) error {
	if err := validateEncryptionKeyInLeaseSet(ls); err != nil {
		return err
	}
	return validateSigningKeyInLeaseSet(ls)
}

// validateEncryptionKeyInLeaseSet checks that the encryption key is non-nil,
// is an ElGamal type, has the correct size, and is not all zeros.
func validateEncryptionKeyInLeaseSet(ls *LeaseSet) error {
	if ls.encryptionKey == nil {
		return oops.Errorf("encryption key is required")
	}
	// LeaseSet v1 mandates ElGamal encryption.
	if !isElGamalKey(ls.encryptionKey) {
		return oops.Errorf("%w: got %T", ErrNonElGamalEncryptionKey, ls.encryptionKey)
	}
	encBytes := ls.encryptionKey.Bytes()
	if len(encBytes) != LEASE_SET_PUBKEY_SIZE {
		return oops.Errorf("invalid encryption key size: got %d, expected %d",
			len(encBytes), LEASE_SET_PUBKEY_SIZE)
	}
	if isAllZero(encBytes) {
		return ErrAllZeroEncryptionKey
	}
	return nil
}

// validateSigningKeyInLeaseSet checks that the signing key is non-nil and
// its size matches the destination certificate's expectation.
func validateSigningKeyInLeaseSet(ls *LeaseSet) error {
	if ls.signingKey == nil {
		return oops.Errorf("signing key is required")
	}
	cert := ls.dest.Certificate()
	kind, err := cert.Type()
	if err != nil {
		return oops.Errorf("invalid certificate type: %w", err)
	}
	expectedSize := determineSigningKeySize(cert, kind)
	actualSize := len(ls.signingKey.Bytes())
	if actualSize != expectedSize {
		return oops.Errorf(
			"%w: got %d bytes, expected %d for cert type %d",
			ErrSigningKeySizeMismatch, actualSize, expectedSize, kind,
		)
	}
	return nil
}

// validateLeaseSetSignature validates the signature if it has been set (non-zero bytes).
func validateLeaseSetSignature(ls *LeaseSet) error {
	if len(ls.signature.Bytes()) > 0 {
		if err := ls.signature.Validate(); err != nil {
			return oops.Errorf("invalid signature: %w", err)
		}
	}
	return nil
}

// IsValid returns true if the LeaseSet is properly initialized and valid.
// This is a convenience method that calls Validate() and returns false if there's an error.
func (ls *LeaseSet) IsValid() bool {
	return ls.Validate() == nil
}

// NewLeaseSet creates a new LeaseSet from the provided components.
// Returns a pointer to LeaseSet for consistency with other constructors.
func NewLeaseSet(
	dest destination.Destination,
	encryptionKey types.ReceivingPublicKey,
	signingKey types.SigningPublicKey,
	leases []lease.Lease,
	signingPrivateKey types.SigningPrivateKey,
) (*LeaseSet, error) {
	log.Debug("Creating new LeaseSet")

	if err := validateLeaseSetInputs(dest, encryptionKey, signingKey, leases); err != nil {
		return nil, err
	}

	// Validate that signingPrivateKey corresponds to the destination's signing public key.
	// A mismatch produces a struct-valid LeaseSet that fails every Verify() call — fail fast.
	if err := validatePrivKeyCorrespondence(dest, signingPrivateKey); err != nil {
		return nil, err
	}

	dbytes, err := serializeLeaseSetData(dest, encryptionKey, signingKey, leases)
	if err != nil {
		return nil, err
	}

	signature, err := createLeaseSetSignature(signingPrivateKey, dbytes)
	if err != nil {
		return nil, err
	}

	leaseSet, err := assembleLeaseSet(dest, encryptionKey, signingKey, leases, signature)
	if err != nil {
		return nil, err
	}

	logLeaseSetCreationSuccess(leaseSet)
	return &leaseSet, nil
}

// validatePrivKeyCorrespondence verifies that signingPrivateKey corresponds to
// the signing public key embedded in dest. Spec: the LeaseSet signature must be
// "signed by the Destination's SigningPrivateKey". A mismatched key produces a
// struct-valid LeaseSet that fails every Verify() call — this helper makes it fail fast.
func validatePrivKeyCorrespondence(dest destination.Destination, signingPrivateKey types.SigningPrivateKey) error {
	derivedPub, err := signingPrivateKey.Public()
	if err != nil {
		return oops.Errorf("failed to derive public key from signing private key: %w", err)
	}
	destPub, err := dest.SigningPublicKey()
	if err != nil {
		return oops.Errorf("failed to retrieve destination signing public key: %w", err)
	}
	if !bytes.Equal(derivedPub.Bytes(), destPub.Bytes()) {
		return oops.Errorf("signing private key does not correspond to destination's signing public key")
	}
	return nil
}

// validateLeaseSetInputs validates all input parameters for LeaseSet creation.
func validateLeaseSetInputs(dest destination.Destination, encryptionKey types.ReceivingPublicKey, signingKey types.SigningPublicKey, leases []lease.Lease) error {
	// Validate destination size
	destBytes, err := dest.KeysAndCert.Bytes()
	if err != nil {
		return oops.Errorf("failed to serialize destination: %w", err)
	}
	if len(destBytes) < 387 {
		return oops.Errorf("invalid destination: minimum size is 387 bytes")
	}

	// Validate encryption key size
	if len(encryptionKey.Bytes()) != LEASE_SET_PUBKEY_SIZE {
		return oops.Errorf("invalid encryption key size")
	}

	// Validate encryption key is ElGamal — LeaseSet v1 requires ElGamal.
	// Non-ElGamal crypto types are only valid in LeaseSet2.
	if !isElGamalKey(encryptionKey) {
		return oops.Errorf("%w: got %T", ErrNonElGamalEncryptionKey, encryptionKey)
	}

	// Validate lease count
	if len(leases) > LEASE_SET_MAX_LEASES {
		return oops.Errorf("invalid lease set: more than 16 leases")
	}

	// Validate signing key type and size match certificate
	return validateSigningKey(dest, signingKey)
}

// validateSigningKey ensures the signing key type and size match the
// Destination certificate's requirements. The I2P spec states:
// "The signing key type is always the same as the destination's signing key type."
func validateSigningKey(dest destination.Destination, signingKey types.SigningPublicKey) error {
	cert := dest.Certificate()
	kind, err := cert.Type()
	if err != nil {
		return oops.Errorf("invalid certificate type: %v", err)
	}

	if kind == certificate.CERT_KEY {
		return validateKeyCertSigningKey(dest, signingKey)
	}
	return validateNullCertSigningKey(signingKey)
}

// validateKeyCertSigningKey validates the signing key size and type against a key
// certificate's requirements.
func validateKeyCertSigningKey(dest destination.Destination, signingKey types.SigningPublicKey) error {
	keyCert, err := key_certificate.KeyCertificateFromCertificate(dest.Certificate())
	if err != nil {
		return oops.Errorf("failed to create key certificate: %w", err)
	}

	expectedSize := keyCert.SigningPublicKeySize()
	if len(signingKey.Bytes()) != expectedSize {
		return oops.Errorf(
			"signing key size mismatch: got %d, expected %d for signing type %d",
			len(signingKey.Bytes()), expectedSize, keyCert.SigningPublicKeyType(),
		)
	}

	if typedKey, ok := signingKey.(interface{ SigningPublicKeyType() int }); ok {
		if typedKey.SigningPublicKeyType() != keyCert.SigningPublicKeyType() {
			return oops.Errorf(
				"signing key type mismatch: key reports type %d, destination requires type %d",
				typedKey.SigningPublicKeyType(), keyCert.SigningPublicKeyType(),
			)
		}
	}
	return nil
}

// validateNullCertSigningKey rejects NULL certificate destinations.
// NULL certificates imply DSA-SHA1 signing, which is legacy crypto.
// Only KEY certificates with modern algorithms (Ed25519, etc.) are supported.
func validateNullCertSigningKey(signingKey types.SigningPublicKey) error {
	return ErrLegacyCryptoNotSupported
}

// serializeLeaseSetData builds the byte array containing all LeaseSet data for signing.
func serializeLeaseSetData(dest destination.Destination, encryptionKey types.ReceivingPublicKey, signingKey types.SigningPublicKey, leases []lease.Lease) ([]byte, error) {
	dbytes := make([]byte, 0)

	// Add Destination
	destBytes, err := dest.KeysAndCert.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize destination: %w", err)
	}
	dbytes = append(dbytes, destBytes...)

	// Add encryption key
	dbytes = append(dbytes, encryptionKey.Bytes()...)

	// Add signing key
	dbytes = append(dbytes, signingKey.Bytes()...)

	// Add lease count
	leaseCount, err := data.NewIntegerFromInt(len(leases), 1)
	if err != nil {
		log.WithError(err).Error("Failed to create lease count")
		return nil, err
	}
	dbytes = append(dbytes, leaseCount.Bytes()...)

	// Add leases
	for _, lease := range leases {
		dbytes = append(dbytes, lease[:]...)
	}

	return dbytes, nil
}

// createLeaseSetSignature generates a signature for the provided data using the private key.
func createLeaseSetSignature(signingPrivateKey types.SigningPrivateKey, dbytes []byte) ([]byte, error) {
	signer, err := signingPrivateKey.NewSigner()
	if err != nil {
		log.WithError(err).Error("Failed to create signer")
		return nil, err
	}

	signature, err := signer.Sign(dbytes)
	if err != nil {
		log.WithError(err).Error("Failed to sign LeaseSet")
		return nil, err
	}

	return signature, nil
}

// assembleLeaseSet creates the final LeaseSet structure from all components.
func assembleLeaseSet(dest destination.Destination, encryptionKey types.ReceivingPublicKey, signingKey types.SigningPublicKey, leases []lease.Lease, signatureBytes []byte) (LeaseSet, error) {
	cert := dest.Certificate()
	signatureVal, err := sig.NewSignatureFromBytes(signatureBytes, getSignatureType(cert))
	if err != nil {
		return LeaseSet{}, oops.Errorf("failed to create signature: %w", err)
	}
	return LeaseSet{
		dest:          dest,
		encryptionKey: defensiveCopyEncryptionKey(encryptionKey),
		signingKey:    signingKey,
		leaseCount:    len(leases),
		leases:        leases,
		signature:     signatureVal,
	}, nil
}

// defensiveCopyEncryptionKey returns an independent copy of the encryption key.
// If the key is a pointer to ElgPublicKey, it is dereferenced to prevent the
// caller from mutating internal LeaseSet state through the retained pointer.
func defensiveCopyEncryptionKey(key types.ReceivingPublicKey) types.ReceivingPublicKey {
	if ptr, ok := key.(*elgamal.ElgPublicKey); ok {
		keyCopy := *ptr
		return keyCopy
	}
	return key
}

// logLeaseSetCreationSuccess logs detailed information about the successfully created LeaseSet.
func logLeaseSetCreationSuccess(leaseSet LeaseSet) {
	destBytes, err := leaseSet.dest.KeysAndCert.Bytes()
	if err != nil {
		log.WithError(err).Warn("Failed to serialize destination for logging")
		return
	}
	log.WithFields(logger.Fields{
		"destination_length":    len(destBytes),
		"encryption_key_length": len(leaseSet.encryptionKey.Bytes()),
		"signing_key_length":    len(leaseSet.signingKey.Bytes()),
		"lease_count":           leaseSet.leaseCount,
	}).Debug("Successfully created new LeaseSet")
}

// isElGamalKey returns true if the key is an ElGamal public key type.
func isElGamalKey(key types.ReceivingPublicKey) bool {
	switch key.(type) {
	case elgamal.ElgPublicKey:
		return true
	case *elgamal.ElgPublicKey:
		return true
	default:
		return false
	}
}

// isAllZero returns true if every byte in the slice is zero.
// An empty or nil slice returns false: there is no key material to check,
// so it must not be mistakenly treated as "all-zero key material".
func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return len(b) > 0
}

// getSignatureType determines the signature type from a certificate
func getSignatureType(cert *certificate.Certificate) int {
	kind, err := cert.Type()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "getSignatureType",
			"reason": "invalid certificate type",
		}).Error("error parsing certificate type")
		return sig.SIGNATURE_TYPE_DSA_SHA1 // Default type
	}
	if kind == certificate.CERT_KEY {
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err == nil {
			return keyCert.SigningPublicKeyType()
		}
	}
	return sig.SIGNATURE_TYPE_DSA_SHA1 // Default type
}

// Bytes returns the LeaseSet as a byte array.
// The lease count byte is derived from len(leases) to guarantee consistency
// between the count byte and the actual lease entries in the output.
func (lease_set LeaseSet) Bytes() ([]byte, error) {
	if lease_set.leaseCount != len(lease_set.leases) {
		return nil, oops.Errorf(
			"%w: count field is %d but have %d leases",
			ErrLeaseCountInvariant, lease_set.leaseCount, len(lease_set.leases),
		)
	}

	var result []byte

	// Add destination
	destBytes, err := lease_set.dest.KeysAndCert.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize destination: %w", err)
	}
	result = append(result, destBytes...)

	// Add encryption key
	result = append(result, lease_set.encryptionKey.Bytes()...)

	// Add signing key
	result = append(result, lease_set.signingKey.Bytes()...)

	// Add lease count — use len(leases) for consistency
	leaseCountInt, err := data.NewIntegerFromInt(len(lease_set.leases), 1)
	if err != nil {
		return nil, err
	}
	result = append(result, leaseCountInt.Bytes()...)

	// Add leases
	for _, lease := range lease_set.leases {
		result = append(result, lease[:]...)
	}

	// Add signature
	result = append(result, lease_set.signature.Bytes()...)

	return result, nil
}

// Destination returns the Destination from the LeaseSet.
func (lease_set LeaseSet) Destination() destination.Destination {
	return lease_set.dest
}

// PublicKey returns the public key as crypto.ElgPublicKey.
// Returns errors encountered during parsing.
func (lease_set LeaseSet) PublicKey() (public_key elgamal.ElgPublicKey, err error) {
	if lease_set.encryptionKey == nil {
		err = oops.Errorf("encryption key is nil")
		return public_key, err
	}

	// Convert to ElgPublicKey
	encKeyBytes := lease_set.encryptionKey.Bytes()
	if len(encKeyBytes) != LEASE_SET_PUBKEY_SIZE {
		err = oops.Errorf("invalid encryption key size: got %d, expected %d", len(encKeyBytes), LEASE_SET_PUBKEY_SIZE)
		return public_key, err
	}

	copy(public_key[:], encKeyBytes)
	log.Debug("Successfully retrieved publicKey from LeaseSet")
	return public_key, err
}

// SigningKey returns the signing public key as crypto.SigningPublicKey.
// returns errors encountered during parsing.
func (lease_set LeaseSet) SigningKey() (signing_public_key types.SigningPublicKey, err error) {
	log.Debug("Retrieving SigningKey from LeaseSet")
	signing_public_key = lease_set.signingKey
	log.Debug("Retrieved signingPublicKey from struct")
	return signing_public_key, err
}

// LeaseCount returns the number of leases specified by the LeaseCount value as int.
func (lease_set LeaseSet) LeaseCount() int {
	return lease_set.leaseCount
}

// Leases returns the leases as []Lease.
func (lease_set LeaseSet) Leases() []lease.Lease {
	return lease_set.leases
}

// Signature returns the signature as Signature.
func (lease_set LeaseSet) Signature() sig.Signature {
	return lease_set.signature
}

// Verify verifies the cryptographic signature of the LeaseSet.
// The signature is computed over all serialised bytes excluding the trailing Signature,
// and is verified against the signing public key from the Destination.
// Returns nil if the signature is valid, or an error describing the verification failure.
func (lease_set LeaseSet) Verify() error {
	log.Debug("Verifying LeaseSet signature")

	// Get the full serialized bytes (includes signature at the end)
	fullBytes, err := lease_set.Bytes()
	if err != nil {
		return oops.Errorf("failed to serialize LeaseSet for verification: %w", err)
	}

	// Get the signature
	signature := lease_set.Signature()
	sigBytes := signature.Bytes()
	sigLen := len(sigBytes)

	if sigLen == 0 || len(fullBytes) < sigLen {
		return oops.Errorf("LeaseSet data too short for signature verification")
	}

	// Data to verify is everything except the trailing signature
	dataToVerify := fullBytes[:len(fullBytes)-sigLen]

	// Get the signing public key from the Destination
	dest := lease_set.Destination()

	signingPubKey, err := dest.SigningPublicKey()
	if err != nil {
		return oops.Errorf("failed to get signing public key from Destination: %w", err)
	}

	return rootcommon.VerifySignatureData(dataToVerify, sigBytes, signingPubKey, "LeaseSet")
}

// Hash returns the SHA-256 hash of the Destination bytes.
// Per the I2P spec, the LeaseSet "is keyed under the SHA256 of the contained
// Destination". This is the netdb lookup key used by floodfill routers.
func (lease_set LeaseSet) Hash() ([32]byte, error) {
	destBytes, err := lease_set.dest.KeysAndCert.Bytes()
	if err != nil {
		return [32]byte{}, oops.Errorf("failed to serialize destination for Hash: %w", err)
	}
	return sha256.Sum256(destBytes), nil
}

// findExpiration iterates leases and returns the Date that satisfies the
// comparison function isBetter, reducing duplication between
// NewestExpiration and OldestExpiration.
func (lease_set LeaseSet) findExpiration(label string, isBetter func(candidate, current time.Time) bool) (data.Date, error) {
	log.Debug("Finding " + label + " expiration in LeaseSet")
	leases := lease_set.leases
	if len(leases) == 0 {
		return data.Date{}, ErrNoLeases
	}
	result := leases[0].Date()
	for _, l := range leases[1:] {
		date := l.Date()
		if isBetter(date.Time(), result.Time()) {
			result = date
		}
	}
	log.WithField(label+"_expiration", result.Time()).Debug("Found " + label + " expiration in LeaseSet")
	return result, nil
}

// NewestExpiration returns the newest lease expiration as an I2P Date.
// If there are no leases, returns epoch zero and ErrNoLeases.
func (lease_set LeaseSet) NewestExpiration() (data.Date, error) {
	return lease_set.findExpiration("newest", func(candidate, current time.Time) bool {
		return candidate.After(current)
	})
}

// OldestExpiration returns the oldest lease expiration as an I2P Date.
// If there are no leases, returns epoch zero and ErrNoLeases.
//
// Per the I2P spec, the earliest expiration of all Leases is treated as the
// timestamp or version of the LeaseSet. Floodfill routers will generally not
// accept a store of a LeaseSet unless it is 'newer' (i.e. has a later
// OldestExpiration) than the currently cached entry. Use OldestExpiration,
// not NewestExpiration, when comparing LeaseSet versions for netdb purposes.
func (lease_set LeaseSet) OldestExpiration() (data.Date, error) {
	return lease_set.findExpiration("oldest", func(candidate, current time.Time) bool {
		return candidate.Before(current)
	})
}
