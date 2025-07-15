// Package lease_set implements the I2P LeaseSet methods and constructor
package lease_set

import (
	"fmt"

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
	"github.com/sirupsen/logrus"
)

var log = logger.GetGoI2PLogger()

// NewLeaseSet creates a new LeaseSet from the provided components.
func NewLeaseSet(
	dest destination.Destination,
	encryptionKey types.ReceivingPublicKey,
	signingKey types.SigningPublicKey,
	leases []lease.Lease,
	signingPrivateKey types.SigningPrivateKey,
) (LeaseSet, error) {
	log.Debug("Creating new LeaseSet")

	if err := validateLeaseSetInputs(dest, encryptionKey, signingKey, leases); err != nil {
		return LeaseSet{}, err
	}

	dbytes, err := serializeLeaseSetData(dest, encryptionKey, signingKey, leases)
	if err != nil {
		return LeaseSet{}, err
	}

	signature, err := createLeaseSetSignature(signingPrivateKey, dbytes)
	if err != nil {
		return LeaseSet{}, err
	}

	leaseSet := assembleLeaseSet(dest, encryptionKey, signingKey, leases, signature)

	logLeaseSetCreationSuccess(leaseSet)
	return leaseSet, nil
}

// validateLeaseSetInputs validates all input parameters for LeaseSet creation.
func validateLeaseSetInputs(dest destination.Destination, encryptionKey types.ReceivingPublicKey, signingKey types.SigningPublicKey, leases []lease.Lease) error {
	// Validate destination size
	if len(dest.KeysAndCert.Bytes()) < 387 {
		return oops.Errorf("invalid destination: minimum size is 387 bytes")
	}

	// Validate encryption key size
	if len(encryptionKey.Bytes()) != LEASE_SET_PUBKEY_SIZE {
		return oops.Errorf("invalid encryption key size")
	}

	// Validate lease count
	if len(leases) > 16 {
		return oops.Errorf("invalid lease set: more than 16 leases")
	}

	// Validate signing key size matches certificate
	return validateSigningKeySize(dest, signingKey)
}

// validateSigningKeySize ensures the signing key size matches the certificate requirements.
func validateSigningKeySize(dest destination.Destination, signingKey types.SigningPublicKey) error {
	cert := dest.Certificate()
	kind, err := cert.Type()
	if err != nil {
		log.WithFields(logrus.Fields{
			"at":     "validateSigningKeySize",
			"reason": "invalid certificate type",
		}).Error("error parsing certificate type")
		return oops.Errorf("invalid certificate type: %v", err)
	}

	if kind == certificate.CERT_KEY {
		// Get expected size from key certificate
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err != nil {
			log.WithError(err).Error("Failed to create keyCert")
		}
		expectedSize := keyCert.SignatureSize()
		if len(signingKey.Bytes()) != expectedSize {
			return oops.Errorf("invalid signing key size: got %d, expected %d",
				len(signingKey.Bytes()), expectedSize)
		}
	} else {
		// Default DSA size
		if len(signingKey.Bytes()) != LEASE_SET_SPK_SIZE {
			return oops.Errorf("invalid signing key size")
		}
	}
	return nil
}

// serializeLeaseSetData builds the byte array containing all LeaseSet data for signing.
func serializeLeaseSetData(dest destination.Destination, encryptionKey types.ReceivingPublicKey, signingKey types.SigningPublicKey, leases []lease.Lease) ([]byte, error) {
	dbytes := make([]byte, 0)

	// Add Destination
	dbytes = append(dbytes, dest.KeysAndCert.Bytes()...)

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
func assembleLeaseSet(dest destination.Destination, encryptionKey types.ReceivingPublicKey, signingKey types.SigningPublicKey, leases []lease.Lease, signature []byte) LeaseSet {
	cert := dest.Certificate()
	return LeaseSet{
		dest:          dest,
		encryptionKey: encryptionKey,
		signingKey:    signingKey,
		leaseCount:    len(leases),
		leases:        leases,
		signature:     sig.NewSignatureFromBytes(signature, getSignatureType(cert)),
	}
}

// logLeaseSetCreationSuccess logs detailed information about the successfully created LeaseSet.
func logLeaseSetCreationSuccess(leaseSet LeaseSet) {
	log.WithFields(logrus.Fields{
		"destination_length":    len(leaseSet.dest.KeysAndCert.Bytes()),
		"encryption_key_length": len(leaseSet.encryptionKey.Bytes()),
		"signing_key_length":    len(leaseSet.signingKey.Bytes()),
		"lease_count":           leaseSet.leaseCount,
	}).Debug("Successfully created new LeaseSet")
}

// getSignatureType determines the signature type from a certificate
func getSignatureType(cert certificate.Certificate) int {
	kind, err := cert.Type()
	if err != nil {
		log.WithFields(logrus.Fields{
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
	result = append(result, lease_set.dest.KeysAndCert.Bytes()...)

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

// Destination returns the Destination as []byte.
func (lease_set LeaseSet) Destination() (dest destination.Destination, err error) {
	dest = lease_set.dest
	log.Debug("Successfully retrieved Destination from LeaseSet")
	return
}

// DestinationDeux returns the destination from the lease set using alternative method.
func (lease_set LeaseSet) DestinationDeux() (dest destination.Destination, err error) {
	fmt.Printf("Starting DestinationDeux\n")

	// Read the Destination from the struct
	dest = lease_set.dest
	fmt.Printf("Successfully retrieved Destination from LeaseSet\n")

	return
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

// LeaseCount returns the numbert of leases specified by the LeaseCount value as int.
// returns errors encountered during parsing.
func (lease_set LeaseSet) LeaseCount() (count int, err error) {
	log.Debug("Retrieving LeaseCount from LeaseSet")
	count = lease_set.leaseCount
	if count > 16 {
		log.WithFields(logrus.Fields{
			"at":          "(LeaseSet) LeaseCount",
			"lease_count": count,
			"reason":      "more than 16 leases",
		}).Warn("invalid lease set")
		err = oops.Errorf("invalid lease set: more than 16 leases")
	} else {
		log.WithField("lease_count", count).Debug("Retrieved LeaseCount from LeaseSet")
	}
	return
}

// Leases returns the leases as []Lease.
// returns errors encountered during parsing.
func (lease_set LeaseSet) Leases() (leases []lease.Lease, err error) {
	log.Debug("Retrieving Leases from LeaseSet")
	leases = lease_set.leases
	log.WithField("lease_count", len(leases)).Debug("Retrieved Leases from LeaseSet")
	return
}

// Signature returns the signature as Signature.
// returns errors encountered during parsing.
func (lease_set LeaseSet) Signature() (signature sig.Signature, err error) {
	log.Debug("Retrieving Signature from LeaseSet")
	signature = lease_set.signature
	log.WithField("signature_length", len(signature.Bytes())).Debug("Retrieved Signature from LeaseSet")
	return
}

// Verify returns nil
func (lease_set LeaseSet) Verify() error {
	log.Debug("Verifying LeaseSet")
	//data_end := len(destination) +
	//	LEASE_SET_PUBKEY_SIZE +
	//	LEASE_SET_SPK_SIZE +
	//	1 +
	//	(44 * lease_set.LeaseCount())
	//data := lease_set[:data_end]
	//spk, _ := lease_set.
	//	Destination().
	//	signingPublicKey()
	//verifier, err := spk.NewVerifier()
	//if err != nil {
	//	return err
	//}
	log.Warn("LeaseSet verification not implemented")
	return nil // verifier.Verify(data, lease_set.Signature())
}

// NewestExpiration returns the newest lease expiration as an I2P Date.
// Returns errors encountered during parsing.
func (lease_set LeaseSet) NewestExpiration() (newest data.Date, err error) {
	log.Debug("Finding newest expiration in LeaseSet")
	leases, err := lease_set.Leases()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve Leases for NewestExpiration")
		return
	}
	newest = data.Date{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, lease := range leases {
		date := lease.Date()
		if date.Time().After(newest.Time()) {
			newest = date
		}
	}
	log.WithField("newest_expiration", newest.Time()).Debug("Found newest expiration in LeaseSet")
	return
}

// OldestExpiration returns the oldest lease expiration as an I2P Date.
// Returns errors encountered during parsing.
func (lease_set LeaseSet) OldestExpiration() (earliest data.Date, err error) {
	log.Debug("Finding oldest expiration in LeaseSet")
	leases, err := lease_set.Leases()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve Leases for OldestExpiration")
		return
	}
	earliest = data.Date{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for _, lease := range leases {
		date := lease.Date()
		if date.Time().Before(earliest.Time()) {
			earliest = date
		}
	}
	log.WithField("oldest_expiration", earliest.Time()).Debug("Found oldest expiration in LeaseSet")
	return
}
