// Package lease_set implements the I2P LeastSet common data structure
package lease_set

import (
	"fmt"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/dsa"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"
	"github.com/sirupsen/logrus"

	"github.com/go-i2p/common/keys_and_cert"
)

var log = logger.GetGoI2PLogger()

// Sizes of various structures in an I2P LeaseSet
const (
	LEASE_SET_PUBKEY_SIZE = 256
	LEASE_SET_SPK_SIZE    = 128
	LEASE_SET_SIG_SIZE    = 40
)

/*
[LeaseSet]
Accurate for version 0.9.49

Description
Contains all of the currently authorized Leases for a particular Destination, the
publicKey to which garlic messages can be encrypted, and then the signingPublicKey
that can be used to revoke this particular version of the structure. The LeaseSet is one
of the two structures stored in the network database (the other being RouterInfo), and
is kered under the SHA256 of the contained Destination.

Contents
Destination, followed by a publicKey for encryption, then a signingPublicKey which
can be used to revoke this version of the LeaseSet, then a 1 byte Integer specifying how
many Lease structures are in the set, followed by the actual Lease structures and
finally a Signature of the previous bytes signed by the Destination's SigningPrivateKey.

+----+----+----+----+----+----+----+----+
| destination                           |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| encryption_key                        |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| signing_key                           |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|num | Lease 0                          |
+----+                                  +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| Lease 1                               |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| Lease ($num-1)                        |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| signature                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+

destination :: Destination
               length -> >= 387 bytes

encryption_key :: publicKey
                  length -> 256 bytes

signing_key :: signingPublicKey
               length -> 128 bytes or as specified in destination's key certificate

num :: Integer
       length -> 1 byte
       Number of leases to follow
       value: 0 <= num <= 16

leases :: [Lease]
          length -> $num*44 bytes

signature :: Signature
             length -> 40 bytes or as specified in destination's key certificate
*/

// LeaseSet is the represenation of an I2P LeaseSet.
//
// https://geti2p.net/spec/common-structures#leaseset
type LeaseSet []byte

/*
type LeaseSet struct {
	Destination *Destination
	EncryptionKey *crypto.ElgPublicKey
	SigningKey *crypto.ElgPublicKey
	Size *Integer
	Leases []*Lease
	Signature *Signature
}
*/

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

	certTotalLength := 3 + int(cert.Length())
	destinationLength := certDataStart + certTotalLength

	fmt.Printf("Certificate details:\n")
	fmt.Printf("  certType: %d\n", cert.Type())
	fmt.Printf("  certLength: %d\n", cert.Length())
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
func (lease_set LeaseSet) Signature() (signature signature.Signature, err error) {
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
	signature = []byte(lease_set[start:end])
	log.WithField("signature_length", len(signature)).Debug("Retrieved Signature from LeaseSet")
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

func ReadLeaseSet(data []byte) (LeaseSet, error) {
	log.Debug("Reading LeaseSet")
	lease_set := LeaseSet(data)
	if len(lease_set) < 387 {
		return nil, oops.Errorf("LeaseSet data too short to contain Destination")
	}
	return lease_set, nil
}
