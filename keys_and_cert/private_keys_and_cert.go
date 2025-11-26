// Package keys_and_cert implements the I2P KeysAndCert common data structure
package keys_and_cert

import (
	"crypto"

	"github.com/samber/oops"
)

// PrivateKeysAndCert contains a KeysAndCert along with the corresponding private keys for the
// Public Key and the Signing Public Key.
type PrivateKeysAndCert struct {
	KeysAndCert
	PK_KEY  crypto.PrivateKey
	SPK_KEY crypto.PrivateKey
}

// NewPrivateKeysAndCert creates a new PrivateKeysAndCert instance.
//
// DEPRECATED: This function is not fully implemented and returns an error.
// Use key generation functions specific to your cryptographic algorithm instead.
// For Ed25519/X25519 keys, use appropriate cryptographic libraries to generate
// private keys and construct the PrivateKeysAndCert manually.
//
// Example:
//
//	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
//	// ... construct KeysAndCert ...
//	pkc := &PrivateKeysAndCert{
//	    KeysAndCert: keysAndCert,
//	    PK_KEY:      encryptionPrivateKey,
//	    SPK_KEY:     privKey,
//	}
func NewPrivateKeysAndCert() (*PrivateKeysAndCert, error) {
	log.Warn("NewPrivateKeysAndCert is not implemented. Use specific key generation functions for your cryptographic algorithm.")
	return nil, oops.Errorf("not implemented - use specific key generation functions (e.g., ed25519.GenerateKey) and construct PrivateKeysAndCert manually")
}
