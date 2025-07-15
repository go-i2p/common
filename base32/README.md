# base32
--
    import "github.com/go-i2p/common/base32"

![base32.svg](base32.svg)

Package base32 implements utilities for encoding and decoding text using I2P's
alphabet.

This package provides I2P-specific base32 encoding/decoding functionality using
RFC 3548 with lowercase characters as specified by the I2P protocol. The
implementation supports encoding binary data to human-readable strings for I2P
destinations, router identifiers, and other network components that require
base32 representation.

Key features: - I2P-compatible base32 alphabet (excludes confusing characters) -
Consistent lowercase encoding for .b32.i2p domain compatibility - Error handling
for invalid input data during decoding operations - High-performance
encoding/decoding suitable for network operations

Common usage patterns:

    encoded := base32.EncodeToString(binaryData)
    decoded, err := base32.DecodeString(encodedString)


Package base32 implements utilities for encoding and decoding text using I2P's
### alphabet

Package base32 implements utilities for encoding and decoding text using I2P's
### alphabet

## Usage

```go
const I2PEncodeAlphabet = "abcdefghijklmnopqrstuvwxyz234567"
```
I2PEncodeAlphabet defines the base32 character set used throughout the I2P
network. This alphabet follows RFC 3548 specifications but uses lowercase
letters for consistency with I2P addressing conventions and .b32.i2p domain
format requirements. The alphabet excludes confusing characters like 0, 1, 8,
and 9 to prevent user errors.

```go
var I2PEncoding *b32.Encoding = b32.NewEncoding(I2PEncodeAlphabet)
```
I2PEncoding provides the standard base32 encoder/decoder used across I2P
components. This encoding instance is configured with the I2P-specific alphabet
and is used for generating destination addresses, router identifiers, and other
base32-encoded data within the I2P ecosystem. It ensures consistent
encoding/decoding behavior.

#### func  DecodeString

```go
func DecodeString(data string) ([]byte, error)
```
DecodeString decodes a base32 string back to binary data using I2P's encoding
alphabet. It converts I2P-compatible base32 strings back to their original byte
representation. Returns an error if the input contains invalid base32 characters
or padding. Example: DecodeString("jbswy3dp") returns []byte{72, 101, 108, 108,
111}, nil

#### func  EncodeToString

```go
func EncodeToString(data []byte) string
```
EncodeToString encodes binary data to a base32 string using I2P's encoding
alphabet. It converts arbitrary byte data into a human-readable base32 string
representation using the I2P-specific lowercase alphabet defined in RFC 3548.
Example: EncodeToString([]byte{72, 101, 108, 108, 111}) returns "jbswy3dp"



base32 

github.com/go-i2p/common/base32

[go-i2p template file](/template.md)
