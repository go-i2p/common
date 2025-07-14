// Package certificate implements the certificate common-structure of I2P.

package certificate

import (
	"encoding/binary"
	"fmt"

	"github.com/samber/oops"
	"github.com/sirupsen/logrus"

	. "github.com/go-i2p/common/data"
)

// readCertificate creates a new Certificate from []byte
// Deprecated: Use ReadCertificate instead. This function will be removed in v2.0.
func readCertificate(data []byte) (certificate Certificate, err error) {
	log.WithFields(logrus.Fields{
		"at":     "readCertificate",
		"reason": "deprecated function called",
	}).Debug("readCertificate is deprecated, use ReadCertificate instead")

	certificate, _, err = ReadCertificate(data)
	return
}

// ReadCertificate creates a Certificate from []byte and returns any ExcessBytes at the end of the input.
// returns err if the certificate could not be read.
func ReadCertificate(data []byte) (certificate Certificate, remainder []byte, err error) {
	certificate = Certificate{}
	switch len(data) {
	case 0:
		certificate.kind = Integer([]byte{0})
		certificate.len = Integer([]byte{0})
		log.WithFields(logrus.Fields{
			"at":                       "(Certificate) ReadCertificate",
			"certificate_bytes_length": len(data),
			"reason":                   "too short (len < CERT_MIN_SIZE)" + fmt.Sprintf("%d", certificate.kind.Int()),
		}).Error("invalid certificate, empty")
		err = oops.Errorf("error parsing certificate: certificate is empty")
		return
	case 1, 2:
		certificate.kind = Integer(data[0 : len(data)-1])
		certificate.len = Integer([]byte{0})
		log.WithFields(logrus.Fields{
			"at":                       "(Certificate) ReadCertificate",
			"certificate_bytes_length": len(data),
			"reason":                   "too short (len < CERT_MIN_SIZE)" + fmt.Sprintf("%d", certificate.kind.Int()),
		}).Error("invalid certificate, too short")
		err = oops.Errorf("error parsing certificate: certificate is too short")
		return
	default:
		certificate.kind = Integer(data[0:1])
		certificate.len = Integer(data[1:3])
		payloadLength := len(data) - CERT_MIN_SIZE
		certificate.payload = data[CERT_MIN_SIZE:]
		if certificate.len.Int() > len(data)-CERT_MIN_SIZE {
			err = oops.Errorf("certificate parsing warning: certificate data is shorter than specified by length")
			log.WithFields(logrus.Fields{
				"at":                         "(Certificate) ReadCertificate",
				"certificate_bytes_length":   certificate.len.Int(),
				"certificate_payload_length": payloadLength,
				"data_bytes:":                string(data),
				"kind_bytes":                 data[0:1],
				"len_bytes":                  data[1:3],
				"reason":                     err.Error(),
			}).Error("invalid certificate, shorter than specified by length")
			return
		}
		log.WithFields(logrus.Fields{
			"type":   certificate.kind.Int(),
			"length": certificate.len.Int(),
		}).Debug("Successfully created new certificate")
	}

	// Handle the case where data longer than specified by length should not be an error
	if err != nil && err.Error() == "certificate parsing warning: certificate data is longer than specified by length" {
		log.Warn("Certificate data longer than specified length")
		err = nil
	}

	// Calculate remainder as data after the complete certificate, not ExcessBytes within payload
	certLength := certificate.length()
	if len(data) > certLength {
		remainder = data[certLength:]
	}

	log.WithFields(logrus.Fields{
		"certificate_length": certLength,
		"input_length":       len(data),
		"remainder_length":   len(remainder),
	}).Debug("Read certificate and calculated remainder")
	return
}

func GetSignatureTypeFromCertificate(cert Certificate) (int, error) {
	if cert.Type() != CERT_KEY {
		return 0, oops.Errorf("unexpected certificate type: %d", cert.Type())
	}
	if len(cert.payload) < 4 {
		return 0, oops.Errorf("certificate payload too short to contain signature type")
	}
	sigType := int(binary.BigEndian.Uint16(cert.payload[0:2])) // Read signing public key type from correct offset
	return sigType, nil
}
