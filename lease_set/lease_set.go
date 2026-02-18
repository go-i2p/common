// Package lease_set implements the I2P LeaseSet methods and constructor
package lease_set

import (
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

// Validate checks if the LeaseSet is properly initialized and valid.
// Returns an error if the lease set is nil or has invalid field values.
func (ls *LeaseSet) Validate() error {
	if ls == nil {
		return oops.Errorf("lease set is nil")
	}
	if ls.leaseCount > LEASE_SET_MAX_LEASES {
		return oops.Errorf("lease set cannot have more than 16 leases")
	}
	if len(ls.leases) != ls.leaseCount {
		return oops.Errorf("lease count mismatch: count field is %d but have %d leases",
			ls.leaseCount, len(ls.leases))
	}
	if ls.encryptionKey == nil {
		return oops.Errorf("encryption key is required")
	}
	if len(ls.encryptionKey.Bytes()) != LEASE_SET_PUBKEY_SIZE {
		return oops.Errorf("invalid encryption key size: got %d, expected %d",
			len(ls.encryptionKey.Bytes()), LEASE_SET_PUBKEY_SIZE)
	}
	if ls.signingKey == nil {
		return oops.Errorf("signing key is required")
	}
	// Only validate signature if it has been set (non-zero)
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
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err != nil {
			return oops.Errorf("failed to create key certificate: %w", err)
		}

		// Validate signing key size
		expectedSize := keyCert.SigningPublicKeySize()
		if len(signingKey.Bytes()) != expectedSize {
			return oops.Errorf(
				"signing key size mismatch: got %d, expected %d for signing type %d",
				len(signingKey.Bytes()), expectedSize, keyCert.SigningPublicKeyType(),
			)
		}

		// Validate signing key type matches by checking the key
		// reports the same type as the destination certificate
		if typedKey, ok := signingKey.(interface{ SigningPublicKeyType() int }); ok {
			if typedKey.SigningPublicKeyType() != keyCert.SigningPublicKeyType() {
				return oops.Errorf(
					"signing key type mismatch: key reports type %d, destination requires type %d",
					typedKey.SigningPublicKeyType(), keyCert.SigningPublicKeyType(),
				)
			}
		}
	} else {
		// Default DSA size for NULL certificate
		if len(signingKey.Bytes()) != LEASE_SET_SPK_SIZE {
			return oops.Errorf("invalid signing key size for NULL certificate: got %d, expected %d",
				len(signingKey.Bytes()), LEASE_SET_SPK_SIZE)
		}
	}
	return nil
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
		encryptionKey: encryptionKey,
		signingKey:    signingKey,
		leaseCount:    len(leases),
		leases:        leases,
		signature:     signatureVal,
	}, nil
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
func (lease_set LeaseSet) Bytes() ([]byte, error) {
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

	// Add lease count
	leaseCountInt, err := data.NewIntegerFromInt(lease_set.leaseCount, 1)
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
		return
	}

	// Convert to ElgPublicKey
	encKeyBytes := lease_set.encryptionKey.Bytes()
	if len(encKeyBytes) != LEASE_SET_PUBKEY_SIZE {
		err = oops.Errorf("invalid encryption key size: got %d, expected %d", len(encKeyBytes), LEASE_SET_PUBKEY_SIZE)
		return
	}

	copy(public_key[:], encKeyBytes)
	log.Debug("Successfully retrieved publicKey from LeaseSet")
	return
}

// SigningKey returns the signing public key as crypto.SigningPublicKey.
// returns errors encountered during parsing.
func (lease_set LeaseSet) SigningKey() (signing_public_key types.SigningPublicKey, err error) {
	log.Debug("Retrieving SigningKey from LeaseSet")
	signing_public_key = lease_set.signingKey
	log.Debug("Retrieved signingPublicKey from struct")
	return
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

	// Create a verifier from the signing public key
	verifier, err := signingPubKey.NewVerifier()
	if err != nil {
		return oops.Errorf("failed to create verifier: %w", err)
	}

	// Verify the signature
	if err := verifier.Verify(dataToVerify, sigBytes); err != nil {
		log.WithError(err).Warn("LeaseSet signature verification failed")
		return oops.Errorf("LeaseSet signature verification failed: %w", err)
	}

	log.Debug("LeaseSet signature verification succeeded")
	return nil
}

// NewestExpiration returns the newest lease expiration as an I2P Date.
// If there are no leases, returns epoch zero and ErrNoLeases.
func (lease_set LeaseSet) NewestExpiration() (newest data.Date, err error) {
	log.Debug("Finding newest expiration in LeaseSet")
	leases := lease_set.leases
	if len(leases) == 0 {
		return data.Date{}, ErrNoLeases
	}
	newest = leases[0].Date()
	for _, l := range leases[1:] {
		date := l.Date()
		if date.Time().After(newest.Time()) {
			newest = date
		}
	}
	log.WithField("newest_expiration", newest.Time()).Debug("Found newest expiration in LeaseSet")
	return
}

// OldestExpiration returns the oldest lease expiration as an I2P Date.
// If there are no leases, returns epoch zero and ErrNoLeases.
func (lease_set LeaseSet) OldestExpiration() (earliest data.Date, err error) {
	log.Debug("Finding oldest expiration in LeaseSet")
	leases := lease_set.leases
	if len(leases) == 0 {
		return data.Date{}, ErrNoLeases
	}
	earliest = leases[0].Date()
	for _, l := range leases[1:] {
		date := l.Date()
		if date.Time().Before(earliest.Time()) {
			earliest = date
		}
	}
	log.WithField("oldest_expiration", earliest.Time()).Debug("Found oldest expiration in LeaseSet")
	return
}
