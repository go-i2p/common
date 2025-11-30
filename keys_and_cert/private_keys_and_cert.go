// Package keys_and_cert implements the I2P KeysAndCert common data structure
package keys_and_cert

import (
	"crypto"
)

// PrivateKeysAndCert contains a KeysAndCert along with the corresponding private keys for the
// Public Key and the Signing Public Key.
type PrivateKeysAndCert struct {
	KeysAndCert
	PK_KEY  crypto.PrivateKey
	SPK_KEY crypto.PrivateKey
}
