// Package offline_signature implements the I2P OfflineSignature common data structure.
package offline_signature

import (
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/signature"
)

// SigningPublicKeySize returns the byte length of a signing public key for the given signature type.
// This function delegates to key_certificate.GetSigningKeySize(), which is the single source of
// truth for the sigtype→key size mapping (mirroring the pattern used by SignatureSize).
// Returns 0 for unknown or unsupported signature types.
//
// Signature types map to signing public key sizes as defined in I2P specification 0.9.67.
// Reference: https://geti2p.net/spec/common-structures#signingpublickey
func SigningPublicKeySize(sigtype uint16) int {
	size, err := key_certificate.GetSigningKeySize(int(sigtype))
	if err != nil {
		return 0
	}
	return size
}

// SignatureSize returns the byte length of a signature for the given signature type.
// This function delegates to signature.SignatureSize(), which is the single source of
// truth for the type→size mapping. Returns 0 for unknown or unsupported signature types.
//
// Signature sizes are defined in I2P specification 0.9.67.
// Reference: https://geti2p.net/spec/common-structures#signature
func SignatureSize(sigtype uint16) int {
	size, err := signature.SignatureSize(int(sigtype))
	if err != nil {
		return 0
	}
	return size
}
