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
	"github.com/go-i2p/crypto/dsa"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"
	"github.com/sirupsen/logrus"

	"github.com/go-i2p/common/keys_and_cert"
)

var log = logger.GetGoI2PLogger()

// NewLeaseSet creates a new LeaseSet from the provided components.
func NewLeaseSet(
	dest destination.Destination,
	encryptionKey types.RecievingPublicKey,
	signingKey types.SigningPublicKey,
	leases []lease.Lease,
	signingPrivateKey types.SigningPrivateKey,
) (LeaseSet, error) {
	log.Debug("Creating new LeaseSet")
	// Validate destination size
	if len(dest.KeysAndCert.Bytes()) < 387 {
		return nil, oops.Errorf("invalid destination: minimum size is 387 bytes")
	}
	// Validate encryption key size
	if len(encryptionKey.Bytes()) != LEASE_SET_PUBKEY_SIZE {
		return nil, oops.Errorf("invalid encryption key size")
	}
	// Validate inputs
	if len(leases) > 16 {
		return nil, oops.Errorf("invalid lease set: more than 16 leases")
	}
	// Validate signing key size matches certificate
	cert := dest.Certificate()
	if cert.Type() == certificate.CERT_KEY {
		// Get expected size from key certificate
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err != nil {
			log.WithError(err).Error("Failed to create keyCert")
		}
		expectedSize := keyCert.SignatureSize()
		if len(signingKey.Bytes()) != expectedSize {
			return nil, oops.Errorf("invalid signing key size: got %d, expected %d",
				len(signingKey.Bytes()), expectedSize)
		}
	} else {
		// Default DSA size
		if len(signingKey.Bytes()) != LEASE_SET_SPK_SIZE {
			return nil, oops.Errorf("invalid signing key size")
		}
	}
	// Build LeaseSet dbytes
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

	// Create signature for all data up to this point
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

	// Add signature
	dbytes = append(dbytes, signature...)

	log.WithFields(logrus.Fields{
		"destination_length":    len(dest.KeysAndCert.Bytes()),
		"encryption_key_length": len(encryptionKey.Bytes()),
		"signing_key_length":    len(signingKey.Bytes()),
		"lease_count":           len(leases),
		"total_length":          len(dbytes),
	}).Debug("Successfully created new LeaseSet")

	return LeaseSet(dbytes), nil
}

// Bytes returns the LeaseSet as a byte array.
func (lease_set LeaseSet) Bytes() ([]byte, error) {
	return []byte(lease_set), nil
}

// Destination returns the Destination as []byte.
func (lease_set LeaseSet) Destination() (dest destination.Destination, err error) {
	keys_and_cert, _, err := keys_and_cert.ReadKeysAndCertElgAndEd25519(lease_set)
	if err != nil {
		log.WithError(err).Error("Failed to read KeysAndCert from LeaseSet")
		return
	}
	dest, _, err = destination.ReadDestination(keys_and_cert.Bytes())
	if err != nil {
		log.WithError(err).Error("Failed to read Destination from KeysAndCert")
	} else {
		log.Debug("Successfully retrieved Destination from LeaseSet")
	}
	return
}

// DestinationDeux returns the destination from the lease set using alternative method.
func (lease_set LeaseSet) DestinationDeux() (dest destination.Destination, err error) {
	data := lease_set

	fmt.Printf("Starting DestinationDeux, lease_set_length=%d\n", len(data))

	// Read the Destination (KeysAndCert) from the LeaseSet
	dest, remainder, err := ReadDestinationFromLeaseSet(data)
	if err != nil {
		fmt.Printf("Failed to read Destination from LeaseSet: %v\n", err)
		return
	}

	fmt.Printf("Successfully retrieved Destination from LeaseSet\n")
	fmt.Printf("  destination_length: %d\n", len(data)-len(remainder))
	fmt.Printf("  remainder_length: %d\n", len(remainder))

	return
}

// PublicKey returns the public key as crypto.ElgPublicKey.
// Returns errors encountered during parsing.
func (lease_set LeaseSet) PublicKey() (public_key elgamal.ElgPublicKey, err error) {
	_, remainder, err := keys_and_cert.ReadKeysAndCert(lease_set)
	remainder_len := len(remainder)
	if remainder_len < LEASE_SET_PUBKEY_SIZE {
		err = oops.Errorf("error parsing public key: not enough data")
		copy(public_key[:], remainder)
		return
	}
	copy(public_key[:], remainder[:LEASE_SET_PUBKEY_SIZE])
	log.Debug("Successfully retrieved publicKey from LeaseSet")
	return
}

// SigningKey returns the signing public key as crypto.SigningPublicKey.
// returns errors encountered during parsing.
func (lease_set LeaseSet) SigningKey() (signing_public_key types.SigningPublicKey, err error) {
	log.Debug("Retrieving SigningKey from LeaseSet")
	destination, err := lease_set.Destination()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve Destination for SigningKey")
		return
	}
	offset := len(destination.Bytes()) + LEASE_SET_PUBKEY_SIZE
	cert := destination.Certificate()
	cert_len := cert.Length()
	if err != nil {
		log.WithError(err).Error("Failed to get Certificate length")
		return
	}
	lease_set_len := len(lease_set)
	if lease_set_len < offset+LEASE_SET_SPK_SIZE {
		log.WithFields(logrus.Fields{
			"at":           "(LeaseSet) SigningKey",
			"data_len":     lease_set_len,
			"required_len": offset + LEASE_SET_SPK_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing signing public key")
		err = oops.Errorf("error parsing signing public key: not enough data")
		return
	}
	if cert_len == 0 {
		// No Certificate is present, return the LEASE_SET_SPK_SIZE byte
		// signingPublicKey space as legacy DSA SHA1 signingPublicKey.
		var dsa_pk dsa.DSAPublicKey
		copy(dsa_pk[:], lease_set[offset:offset+LEASE_SET_SPK_SIZE])
		signing_public_key = dsa_pk
		log.Debug("Retrieved legacy DSA SHA1 signingPublicKey")
	} else {
		// A Certificate is present in this LeaseSet's Destination
		cert_type := cert.Type()
		if cert_type == certificate.CERT_KEY {
			// This LeaseSet's Destination's Certificate is a Key Certificate,
			// create the signing publickey key using any data that might be
			// contained in the key certificate.
			keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
			if err != nil {
				log.WithError(err).Error("Failed to create keyCert")
			}
			signing_public_key, err = keyCert.ConstructSigningPublicKey(
				lease_set[offset : offset+LEASE_SET_SPK_SIZE],
			)
			if err != nil {
				log.WithError(err).Error("Failed to construct signingPublicKey from keyCertificate")
			} else {
				log.Debug("Retrieved signingPublicKey from keyCertificate")
			}
		} else {
			// No Certificate is present, return the LEASE_SET_SPK_SIZE byte
			// signingPublicKey space as legacy DSA SHA1 signingPublicKey.
			var dsa_pk dsa.DSAPublicKey
			copy(dsa_pk[:], lease_set[offset:offset+LEASE_SET_SPK_SIZE])
			signing_public_key = dsa_pk
			log.Debug("Retrieved legacy DSA SHA1 signingPublicKey (Certificate present but not Key Certificate)")
		}
	}
	return
}

// LeaseCount returns the numbert of leases specified by the LeaseCount value as int.
// returns errors encountered during parsing.
func (lease_set LeaseSet) LeaseCount() (count int, err error) {
	log.Debug("Retrieving LeaseCount from LeaseSet")
	_, remainder, err := keys_and_cert.ReadKeysAndCert(lease_set)
	if err != nil {
		log.WithError(err).Error("Failed to read KeysAndCert for LeaseCount")
		return
	}
	remainder_len := len(remainder)
	if remainder_len < LEASE_SET_PUBKEY_SIZE+LEASE_SET_SPK_SIZE+1 {
		log.WithFields(logrus.Fields{
			"at":           "(LeaseSet) LeaseCount",
			"data_len":     remainder_len,
			"required_len": LEASE_SET_PUBKEY_SIZE + LEASE_SET_SPK_SIZE + 1,
			"reason":       "not enough data",
		}).Error("error parsing lease count")
		err = oops.Errorf("error parsing lease count: not enough data")
		return
	}
	c := data.Integer([]byte{remainder[LEASE_SET_PUBKEY_SIZE+LEASE_SET_SPK_SIZE]})
	count = c.Int()
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
	destination, err := lease_set.Destination()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve Destination for Leases")
		return
	}
	offset := len(destination.Bytes()) + LEASE_SET_PUBKEY_SIZE + LEASE_SET_SPK_SIZE + 1
	count, err := lease_set.LeaseCount()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve LeaseCount for Leases")
		return
	}
	for i := 0; i < count; i++ {
		start := offset + (i * lease.LEASE_SIZE)
		end := start + lease.LEASE_SIZE
		lease_set_len := len(lease_set)
		if lease_set_len < end {
			log.WithFields(logrus.Fields{
				"at":           "(LeaseSet) Leases",
				"data_len":     lease_set_len,
				"required_len": end,
				"reason":       "some leases missing",
			}).Error("error parsnig lease set")
			err = oops.Errorf("error parsing lease set: some leases missing")
			return
		}
		var lease lease.Lease
		copy(lease[:], lease_set[start:end])
		leases = append(leases, lease)
	}
	log.WithField("lease_count", len(leases)).Debug("Retrieved Leases from LeaseSet")
	return
}

// Signature returns the signature as Signature.
// returns errors encountered during parsing.
func (lease_set LeaseSet) Signature() (signature sig.Signature, err error) {
	log.Debug("Retrieving Signature from LeaseSet")
	destination, err := lease_set.Destination()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve Destination for Signature")
		return
	}
	lease_count, err := lease_set.LeaseCount()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve LeaseCount for Signature")
		return
	}
	start := len(destination.Bytes()) +
		LEASE_SET_PUBKEY_SIZE +
		LEASE_SET_SPK_SIZE +
		1 +
		(lease.LEASE_SIZE * lease_count)
	cert := destination.Certificate()
	cert_type := cert.Type()
	var end int
	if cert_type == certificate.CERT_KEY {
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err != nil {
			log.WithError(err).Error("Failed to create keyCert")
		}
		end = start + keyCert.SignatureSize()
	} else {
		end = start + LEASE_SET_SIG_SIZE
	}
	lease_set_len := len(lease_set)
	if lease_set_len < end {
		log.WithFields(logrus.Fields{
			"at":           "(LeaseSet) Signature",
			"data_len":     lease_set_len,
			"required_len": end,
			"reason":       "not enough data",
		}).Error("error parsing signatre")
		err = oops.Errorf("error parsing signature: not enough data")
		return
	}
	// Note: In LeaseSet context, signature type must be inferred from the destination's certificate
	signatureBytes := []byte(lease_set[start:end])

	// Determine signature type from certificate
	var sigType int = sig.SIGNATURE_TYPE_DSA_SHA1 // Default type
	if cert_type == certificate.CERT_KEY {
		keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
		if err == nil {
			// Extract the actual signature type from the key certificate
			sigType = keyCert.SigningPublicKeyType()
			log.WithField("signature_type", sigType).Debug("Extracted signature type from key certificate")
		} else {
			log.WithError(err).Warn("Failed to extract signature type from key certificate, using default")
		}
	} else {
		log.Debug("Using default DSA SHA1 signature type (no key certificate)")
	}

	signature = sig.NewSignatureFromBytes(signatureBytes, sigType)
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
