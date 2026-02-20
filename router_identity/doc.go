/*
Package router_identity implements the I2P RouterIdentity common data structure.

The RouterIdentity structure uniquely identifies a particular I2P router.
It is structurally identical to KeysAndCert and contains an encryption
public key, a signing public key, optional padding, and a certificate.

Spec reference: https://geti2p.net/spec/common-structures#routeridentity

# Key Type Restrictions

RouterIdentities have stricter key type requirements than the generic
KeysAndCert structure. Per the I2P specification (0.9.67):

  - RedDSA (signing type 11) is for Destinations and encrypted leasesets only;
    never used for Router Identities.
  - RSA signing types (4-6) are offline only; never used in Key Certificates
    for Router Identities.
  - Ed25519ph (signing type 8) is offline only; never used in Key Certificates
    for Router Identities.
  - MLKEM hybrid crypto types (5-7) are for LeaseSets only, not for Router
    Identities or Destinations.
  - ElGamal (crypto type 0) and DSA-SHA1 (signing type 0) are deprecated
    for new Router Identities but still accepted for backward compatibility.

The recommended key types for new Router Identities are Ed25519 (signing
type 7) and X25519 (crypto type 4).

# Design Notes

RouterIdentity wraps *keys_and_cert.KeysAndCert as an embedded pointer.
This provides access to all KeysAndCert methods while adding RouterIdentity-specific
validation and key type enforcement.

Constructors (NewRouterIdentity, NewRouterIdentityFromKeysAndCert) perform
defensive deep copies of the provided data, so callers may freely mutate
their inputs after construction without affecting the RouterIdentity.

AsDestination() also performs a deep copy, cloning the KeyCertificate pointer
and Padding slice backing array. The returned Destination is independent of
the original RouterIdentity.

# Usage

	// Create from explicit parameters (recommended for new identities):
	ri, err := router_identity.NewRouterIdentityWithCompressiblePadding(
	    publicKey, signingPublicKey, cert)

	// Create from existing KeysAndCert:
	ri, err := router_identity.NewRouterIdentityFromKeysAndCert(kac)

	// Parse from wire format:
	ri, remainder, err := router_identity.ReadRouterIdentity(data)

	// Get the identity hash (for NetDB lookups):
	hash, err := ri.Hash()

	// Serialize to wire format:
	wireBytes, err := ri.Bytes()

	// Convert to Destination (deep copy):
	dest := ri.AsDestination()
*/
package router_identity
