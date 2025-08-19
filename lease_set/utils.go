// Package lease_set utility functions
package lease_set

import (
	"fmt"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/lease"
	sig "github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/dsa"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

// ReadDestinationFromLeaseSet reads the destination from lease set data.
func ReadDestinationFromLeaseSet(data []byte) (dest destination.Destination, remainder []byte, err error) {
	fmt.Printf("Reading Destination from LeaseSet, input_length=%d\n", len(data))

	if len(data) < 387 { // Minimum size of Destination (384 keys + 3 bytes for minimum certificate)
		err = oops.Errorf("LeaseSet data too short to contain Destination")
		fmt.Printf("Error: %v\n", err)
		return
	}

	certDataStart := 384
	certData := data[certDataStart:]

	cert, _, err := certificate.ReadCertificate(certData)
	if err != nil {
		fmt.Printf("Failed to read Certificate from LeaseSet: %v\n", err)
		return
	}

	kind, err := cert.Type()
	if err != nil {
		fmt.Printf("Error reading certificate type: %v\n", err)
		return
	}
	certLength, err := cert.Length()
	if err != nil {
		fmt.Printf("Failed to read Certificate Length: %v\n", err)
		return
	}

	certTotalLength := 3 + int(certLength)
	destinationLength := certDataStart + certTotalLength

	fmt.Printf("Certificate details:\n")
	fmt.Printf("  certType: %d\n", kind)
	fmt.Printf("  certLength: %d\n", certLength)
	fmt.Printf("  certTotalLength: %d\n", certTotalLength)
	fmt.Printf("  destinationLength: %d\n", destinationLength)

	if len(data) < destinationLength {
		err = oops.Errorf("LeaseSet data too short to contain full Destination")
		fmt.Printf("Error: %v\n", err)
		return
	}

	destinationData := data[:destinationLength]

	keysAndCert, _, err := keys_and_cert.ReadKeysAndCert(destinationData)
	if err != nil {
		fmt.Printf("Failed to read KeysAndCert: %v\n", err) // 32 / 0 error
		return
	}

	dest = destination.Destination{
		KeysAndCert: keysAndCert,
	}

	remainder = data[destinationLength:]

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

	signature, err := parseSignature(remainder, dest)
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

	var encKeyBytes [LEASE_SET_PUBKEY_SIZE]byte
	copy(encKeyBytes[:], data[:LEASE_SET_PUBKEY_SIZE])
	encryptionKey := elgamal.ElgPublicKey(encKeyBytes)
	remainder := data[LEASE_SET_PUBKEY_SIZE:]

	return encryptionKey, remainder, nil
}

// parseSigningKey extracts and constructs the signing key based on certificate type.
func parseSigningKey(data []byte, dest destination.Destination) (types.SigningPublicKey, []byte, error) {
	cert := dest.Certificate()
	kind, err := cert.Type()
	if err != nil {
		log.WithFields(logrus.Fields{
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
func determineSigningKeySize(cert certificate.Certificate, kind int) int {
	if kind == certificate.CERT_KEY {
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err == nil {
			return keyCert.SignatureSize()
		}
	}
	return LEASE_SET_SPK_SIZE
}

// constructSigningKey builds the appropriate signing key based on certificate type.
func constructSigningKey(keyData []byte, cert certificate.Certificate, kind int) (types.SigningPublicKey, error) {
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
	var dsaKey [LEASE_SET_SPK_SIZE]byte
	copy(dsaKey[:], keyData)
	return dsa.DSAPublicKey(dsaKey), nil
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
func parseSignature(data []byte, dest destination.Destination) (sig.Signature, error) {
	cert := dest.Certificate()
	kind, _ := cert.Type()

	sigSize := determineSignatureSize(cert, kind)
	if len(data) < sigSize {
		return sig.Signature{}, oops.Errorf("LeaseSet data too short for signature")
	}

	sigType := determineSignatureType(cert, kind)
	return sig.NewSignatureFromBytes(data[:sigSize], sigType), nil
}

// determineSignatureSize calculates the signature size based on certificate type.
func determineSignatureSize(cert certificate.Certificate, kind int) int {
	if kind == certificate.CERT_KEY {
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err == nil {
			return keyCert.SignatureSize()
		}
	}
	return LEASE_SET_SIG_SIZE
}

// determineSignatureType returns the appropriate signature type for the certificate.
func determineSignatureType(cert certificate.Certificate, kind int) int {
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
