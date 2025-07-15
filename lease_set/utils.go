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

	if len(data) < 387 {
		return LeaseSet{}, oops.Errorf("LeaseSet data too short to contain Destination")
	}

	// Parse destination
	dest, remainder, err := ReadDestinationFromLeaseSet(data)
	if err != nil {
		return LeaseSet{}, oops.Errorf("failed to read destination: %w", err)
	}

	// Parse encryption key (256 bytes)
	if len(remainder) < LEASE_SET_PUBKEY_SIZE {
		return LeaseSet{}, oops.Errorf("LeaseSet data too short for encryption key")
	}
	var encKeyBytes [LEASE_SET_PUBKEY_SIZE]byte
	copy(encKeyBytes[:], remainder[:LEASE_SET_PUBKEY_SIZE])
	encryptionKey := elgamal.ElgPublicKey(encKeyBytes)
	remainder = remainder[LEASE_SET_PUBKEY_SIZE:]

	// Parse signing key (128 bytes or variable based on certificate)
	sigKeySize := LEASE_SET_SPK_SIZE
	cert := dest.Certificate()
	kind, err := cert.Type()
	if err != nil {
		log.WithFields(logrus.Fields{
			"at":     "ReadLeaseSet",
			"reason": "invalid certificate type",
		}).Error("error parsing certificate type")
		return LeaseSet{}, oops.Errorf("invalid certificate type: %v", err)
	}
	if kind == certificate.CERT_KEY {
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err == nil {
			sigKeySize = keyCert.SignatureSize()
		}
	}

	if len(remainder) < sigKeySize {
		return LeaseSet{}, oops.Errorf("LeaseSet data too short for signing key")
	}

	var signingKey types.SigningPublicKey
	if kind == certificate.CERT_KEY {
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err == nil {
			signingKey, err = keyCert.ConstructSigningPublicKey(remainder[:sigKeySize])
			if err != nil {
				return LeaseSet{}, oops.Errorf("failed to construct signing key: %w", err)
			}
		}
	} else {
		// Default DSA key
		var dsaKey [LEASE_SET_SPK_SIZE]byte
		copy(dsaKey[:], remainder[:LEASE_SET_SPK_SIZE])
		signingKey = dsa.DSAPublicKey(dsaKey)
	}
	remainder = remainder[sigKeySize:]

	// Parse lease count (1 byte)
	if len(remainder) < 1 {
		return LeaseSet{}, oops.Errorf("LeaseSet data too short for lease count")
	}
	leaseCount := int(remainder[0])
	if leaseCount > 16 {
		return LeaseSet{}, oops.Errorf("invalid lease count: %d (max 16)", leaseCount)
	}
	remainder = remainder[1:]

	// Parse leases
	if len(remainder) < leaseCount*lease.LEASE_SIZE {
		return LeaseSet{}, oops.Errorf("LeaseSet data too short for leases")
	}

	var leases []lease.Lease
	for i := 0; i < leaseCount; i++ {
		var l lease.Lease
		copy(l[:], remainder[i*lease.LEASE_SIZE:(i+1)*lease.LEASE_SIZE])
		leases = append(leases, l)
	}
	remainder = remainder[leaseCount*lease.LEASE_SIZE:]

	// Parse signature
	sigSize := LEASE_SET_SIG_SIZE
	if kind == certificate.CERT_KEY {
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err == nil {
			sigSize = keyCert.SignatureSize()
		}
	}

	if len(remainder) < sigSize {
		return LeaseSet{}, oops.Errorf("LeaseSet data too short for signature")
	}

	sigType := sig.SIGNATURE_TYPE_DSA_SHA1
	if kind == certificate.CERT_KEY {
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err == nil {
			sigType = keyCert.SigningPublicKeyType()
		}
	}

	signature := sig.NewSignatureFromBytes(remainder[:sigSize], sigType)

	leaseSet := LeaseSet{
		dest:          dest,
		encryptionKey: encryptionKey,
		signingKey:    signingKey,
		leaseCount:    leaseCount,
		leases:        leases,
		signature:     signature,
	}

	return leaseSet, nil
}
