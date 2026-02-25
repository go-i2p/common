// Package key_certificate implements the I2P KeyCertificate common data structure
package key_certificate

/*
I2P Key Certificate (CERT_KEY, type 5) payload format
https://geti2p.net/spec/common-structures#certificate
Accurate for version 0.9.67

The KEY certificate payload encodes the signing and crypto key types:

+----+----+----+----+
| sig_type (2)      |
+----+----+----+----+
| crypto_type (2)   |
+----+----+----+----+

sig_type :: Integer
            length -> 2 bytes, big-endian
            value  -> signing algorithm type (e.g. 7 = Ed25519)

crypto_type :: Integer
               length -> 2 bytes, big-endian
               value  -> encryption algorithm type (e.g. 4 = X25519)
*/
