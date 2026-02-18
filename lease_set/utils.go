// Package lease_set utility functions
package lease_set

import (
	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/lease"
	sig "github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/dsa"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// validateDestinationMinSize validates that data has minimum size for destination parsing.
// Returns error if data is too short to contain a valid destination.
func validateDestinationMinSize(dataLen int) error {
	const minDestinationSize = 387
	if dataLen < minDestinationSize {
		log.WithFields(logger.Fields{
			"data_len": dataLen,
			"min_size": minDestinationSize,
		}).Error("LeaseSet data too short to contain Destination")
		return oops.Errorf("LeaseSet data too short to contain Destination")
	}
	return nil
}

// parseCertificateFromLeaseSet extracts and validates the certificate from lease set data.
// Returns the certificate type, length, and any error encountered.
func parseCertificateFromLeaseSet(data []byte, certDataStart int) (int, int, error) {
	certData := data[certDataStart:]
	cert, _, err := certificate.ReadCertificate(certData)
	if err != nil {
		log.WithError(err).Error("Failed to read Certificate from LeaseSet")
		return 0, 0, err
	}

	kind, err := cert.Type()
	if err != nil {
		log.WithError(err).Error("Error reading certificate type")
		return 0, 0, err
	}

	certLength, err := cert.Length()
	if err != nil {
		log.WithError(err).Error("Failed to read Certificate Length")
		return 0, 0, err
	}

	return kind, int(certLength), nil
}

// calculateDestinationLength computes the total destination length from certificate data.
// Returns the calculated length and logs debug information.
func calculateDestinationLength(certDataStart int, certLength int) int {
	certTotalLength := 3 + certLength
	destinationLength := certDataStart + certTotalLength

	log.WithFields(logger.Fields{
		"cert_length":        certLength,
		"cert_total_length":  certTotalLength,
		"destination_length": destinationLength,
	}).Debug("Certificate details")

	return destinationLength
}

// validateDestinationDataSize validates that data contains the full destination.
// Returns error if data is too short for the calculated destination length.
func validateDestinationDataSize(dataLen, destinationLength int) error {
	if dataLen < destinationLength {
		log.WithFields(logger.Fields{
			"data_len":           dataLen,
			"destination_length": destinationLength,
		}).Error("LeaseSet data too short to contain full Destination")
		return oops.Errorf("LeaseSet data too short to contain full Destination")
	}
	return nil
}

// extractDestinationFromData reads the destination and calculates remainder.
// Returns the destination, remaining data, and any error encountered.
func extractDestinationFromData(data []byte, destinationLength int) (destination.Destination, []byte, error) {
	destinationData := data[:destinationLength]
	keysAndCert, _, err := keys_and_cert.ReadKeysAndCert(destinationData)
	if err != nil {
		log.WithError(err).Error("Failed to read KeysAndCert")
		return destination.Destination{}, nil, err
	}

	dest := destination.Destination{
		KeysAndCert: keysAndCert,
	}
	remainder := data[destinationLength:]

	return dest, remainder, nil
}

// ReadDestinationFromLeaseSet reads the destination from lease set data.
func ReadDestinationFromLeaseSet(data []byte) (dest destination.Destination, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Reading Destination from LeaseSet")

	if err = validateDestinationMinSize(len(data)); err != nil {
		return
	}

	const certDataStart = 384
	kind, certLength, err := parseCertificateFromLeaseSet(data, certDataStart)
	if err != nil {
		return
	}
	log.WithField("cert_type", kind).Debug("Parsed certificate from LeaseSet")

	destinationLength := calculateDestinationLength(certDataStart, certLength)

	if err = validateDestinationDataSize(len(data), destinationLength); err != nil {
		return
	}

	dest, remainder, err = extractDestinationFromData(data, destinationLength)
	return
}

// ReadLeaseSet reads a lease set from byte data.
func ReadLeaseSet(data []byte) (LeaseSet, error) {
	log.Debug("Reading LeaseSet")

	if err := validateLeaseSetDataLength(data); err != nil {
		return LeaseSet{}, err
	}

	dest, remainder, err := ReadDestinationFromLeaseSet(data)
	if err != nil {
		return LeaseSet{}, oops.Errorf("failed to read destination: %w", err)
	}

	encryptionKey, remainder, err := parseEncryptionKey(remainder)
	if err != nil {
		return LeaseSet{}, err
	}

	signingKey, remainder, err := parseSigningKey(remainder, dest)
	if err != nil {
		return LeaseSet{}, err
	}

	leaseCount, leases, remainder, err := parseLeases(remainder)
	if err != nil {
		return LeaseSet{}, err
	}

	signature, _, err := parseSignature(remainder, dest)
	if err != nil {
		return LeaseSet{}, err
	}

	return assembleLeaseSetFromParsedData(dest, encryptionKey, signingKey, leaseCount, leases, signature), nil
}

// validateLeaseSetDataLength checks if data has minimum required length for a LeaseSet.
func validateLeaseSetDataLength(data []byte) error {
	if len(data) < 387 {
		return oops.Errorf("LeaseSet data too short to contain Destination")
	}
	return nil
}

// parseEncryptionKey extracts and validates the encryption key from lease set data.
func parseEncryptionKey(data []byte) (elgamal.ElgPublicKey, []byte, error) {
	if len(data) < LEASE_SET_PUBKEY_SIZE {
		return elgamal.ElgPublicKey{}, nil, oops.Errorf("LeaseSet data too short for encryption key")
	}

	encKeyBytes := data[:LEASE_SET_PUBKEY_SIZE]
	encryptionKeyPtr, err := elgamal.NewElgPublicKey(encKeyBytes)
	if err != nil {
		return elgamal.ElgPublicKey{}, nil, oops.Wrapf(err, "failed to construct ElGamal public key")
	}
	remainder := data[LEASE_SET_PUBKEY_SIZE:]

	// NewElgPublicKey returns a pointer, dereference it
	return *encryptionKeyPtr, remainder, nil
}

// parseSigningKey extracts and constructs the signing key based on certificate type.
func parseSigningKey(data []byte, dest destination.Destination) (types.SigningPublicKey, []byte, error) {
	cert := dest.Certificate()
	kind, err := cert.Type()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "parseSigningKey",
			"reason": "invalid certificate type",
		}).Error("error parsing certificate type")
		return nil, nil, oops.Errorf("invalid certificate type: %v", err)
	}

	sigKeySize := determineSigningKeySize(cert, kind)
	if len(data) < sigKeySize {
		return nil, nil, oops.Errorf("LeaseSet data too short for signing key")
	}

	signingKey, err := constructSigningKey(data[:sigKeySize], cert, kind)
	if err != nil {
		return nil, nil, err
	}

	return signingKey, data[sigKeySize:], nil
}

// determineSigningKeySize calculates the signing key size based on certificate type.
func determineSigningKeySize(cert *certificate.Certificate, kind int) int {
	if kind == certificate.CERT_KEY {
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err == nil {
			return keyCert.SigningPublicKeySize()
		}
	}
	return LEASE_SET_SPK_SIZE
}

// constructSigningKey builds the appropriate signing key based on certificate type.
func constructSigningKey(keyData []byte, cert *certificate.Certificate, kind int) (types.SigningPublicKey, error) {
	if kind == certificate.CERT_KEY {
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err == nil {
			signingKey, err := keyCert.ConstructSigningPublicKey(keyData)
			if err != nil {
				return nil, oops.Errorf("failed to construct signing key: %w", err)
			}
			return signingKey, nil
		}
	}

	// Default DSA key
	dsaKey, err := dsa.NewDSAPublicKey(keyData)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct DSA public key")
	}
	return dsaKey, nil
}

// parseLeases extracts the lease count and individual leases from the data.
func parseLeases(data []byte) (int, []lease.Lease, []byte, error) {
	if len(data) < 1 {
		return 0, nil, nil, oops.Errorf("LeaseSet data too short for lease count")
	}

	leaseCount := int(data[0])
	if leaseCount > 16 {
		return 0, nil, nil, oops.Errorf("invalid lease count: %d (max 16)", leaseCount)
	}

	remainder := data[1:]
	if len(remainder) < leaseCount*lease.LEASE_SIZE {
		return 0, nil, nil, oops.Errorf("LeaseSet data too short for leases")
	}

	leases := extractLeases(remainder, leaseCount)
	remainder = remainder[leaseCount*lease.LEASE_SIZE:]

	return leaseCount, leases, remainder, nil
}

// extractLeases copies lease data into individual lease structures.
func extractLeases(data []byte, leaseCount int) []lease.Lease {
	var leases []lease.Lease
	for i := 0; i < leaseCount; i++ {
		var l lease.Lease
		copy(l[:], data[i*lease.LEASE_SIZE:(i+1)*lease.LEASE_SIZE])
		leases = append(leases, l)
	}
	return leases
}

// parseSignature extracts and creates the signature from the remaining data.
// Returns the parsed signature, any remaining bytes after the signature, and an error.
func parseSignature(data []byte, dest destination.Destination) (sig.Signature, []byte, error) {
	cert := dest.Certificate()
	kind, err := cert.Type()
	if err != nil {
		log.WithError(err).Error("failed to read certificate type in parseSignature")
		return sig.Signature{}, data, oops.Errorf("failed to read certificate type: %w", err)
	}

	sigSize := determineSignatureSize(cert, kind)
	if len(data) < sigSize {
		return sig.Signature{}, data, oops.Errorf("LeaseSet data too short for signature: need %d, got %d", sigSize, len(data))
	}

	remainder := data[sigSize:]
	if len(remainder) > 0 {
		log.WithFields(logger.Fields{
			"trailing_bytes": len(remainder),
		}).Warn("LeaseSet has trailing data after signature")
	}

	sigType := determineSignatureType(cert, kind)
	sigVal, err := sig.NewSignatureFromBytes(data[:sigSize], sigType)
	if err != nil {
		return sig.Signature{}, data, oops.Errorf("failed to create signature: %w", err)
	}
	return sigVal, remainder, nil
}

// determineSignatureSize calculates the signature size based on certificate type.
func determineSignatureSize(cert *certificate.Certificate, kind int) int {
	if kind == certificate.CERT_KEY {
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err == nil {
			return keyCert.SignatureSize()
		}
	}
	return LEASE_SET_SIG_SIZE
}

// determineSignatureType returns the appropriate signature type for the certificate.
func determineSignatureType(cert *certificate.Certificate, kind int) int {
	if kind == certificate.CERT_KEY {
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err == nil {
			return keyCert.SigningPublicKeyType()
		}
	}
	return sig.SIGNATURE_TYPE_DSA_SHA1
}

// assembleLeaseSetFromParsedData creates the final LeaseSet structure from parsed components.
func assembleLeaseSetFromParsedData(dest destination.Destination, encryptionKey elgamal.ElgPublicKey, signingKey types.SigningPublicKey, leaseCount int, leases []lease.Lease, signature sig.Signature) LeaseSet {
	return LeaseSet{
		dest:          dest,
		encryptionKey: encryptionKey,
		signingKey:    signingKey,
		leaseCount:    leaseCount,
		leases:        leases,
		signature:     signature,
	}
}
