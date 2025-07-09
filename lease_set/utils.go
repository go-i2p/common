// Package lease_set utility functions
package lease_set

import (
	"fmt"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/samber/oops"
)

// ReadDestinationFromLeaseSet reads the destination from lease set data.
//
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

// ReadLeaseSet reads a lease set from byte data.
//
func ReadLeaseSet(data []byte) (LeaseSet, error) {
	log.Debug("Reading LeaseSet")
	lease_set := LeaseSet(data)
	if len(lease_set) < 387 {
		return nil, oops.Errorf("LeaseSet data too short to contain Destination")
	}
	return lease_set, nil
}
