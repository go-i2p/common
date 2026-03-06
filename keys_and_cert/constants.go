package keys_and_cert

import "github.com/go-i2p/common/certificate"

// Sizes of various KeysAndCert structures and requirements
const (
	KEYS_AND_CERT_PUBKEY_SIZE = 256
	KEYS_AND_CERT_SPK_SIZE    = 128
	// KEYS_AND_CERT_MIN_SIZE is the minimum valid wire size: the 384-byte
	// data block plus a 3-byte minimum (NULL) certificate.
	KEYS_AND_CERT_MIN_SIZE  = KEYS_AND_CERT_DATA_SIZE + certificate.CERT_MIN_SIZE
	KEYS_AND_CERT_DATA_SIZE = 384
)
