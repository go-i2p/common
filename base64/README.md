# base64
--
    import "github.com/go-i2p/common/base64"

![base64.svg](base64.svg)

Package base64 implements I2P-specific base64 encoding and decoding utilities.

This package provides base64 functionality tailored for the I2P (Invisible
Internet Project) network, implementing a modified RFC 4648 base64 alphabet that
ensures compatibility with I2P protocols and addressing schemes. The key
modifications replace problematic characters: "/" becomes "~" to avoid
filesystem conflicts, and "+" becomes "-" for URL-safe encoding without
percent-encoding requirements.

The package is essential for handling I2P destination addresses, router
identifiers, cryptographic key material, and binary data serialization
throughout the I2P ecosystem. All encoding operations maintain standard base64
semantics while using the I2P-specific character set.

Usage patterns:

    - Encoding binary data for I2P network transmission
    - Generating .b64.i2p destination addresses
    - Converting cryptographic keys to string representation
    - Serializing router information and network database entries

The implementation emphasizes performance and thread safety, providing reusable
encoder instances that can be safely used across concurrent operations without
synchronization overhead.


Package base64 constants

Package base64 utilities and encoding instances

## Usage

```go
const I2PEncodeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~"
```
I2PEncodeAlphabet defines the I2P-specific base64 character set used throughout
the network. This alphabet follows RFC 4648 standard base64 encoding with two
critical modifications: - "/" is replaced with "~" to avoid filesystem path
conflicts - "+" is replaced with "-" to ensure URL-safe encoding without
percent-encoding The alphabet maintains the standard ordering: A-Z (0-25), a-z
(26-51), 0-9 (52-61), - (62), ~ (63). This encoding is essential for I2P
destination addresses, router identifiers, and network data structures. Example
usage: Used in .b64.i2p addresses and binary data serialization across I2P
protocols.

```go
var I2PEncoding *b64.Encoding = b64.NewEncoding(I2PEncodeAlphabet)
```
I2PEncoding provides the standard base64 encoder/decoder instance for all I2P
components. This encoding instance is pre-configured with the I2P-specific
alphabet and optimizes performance by reusing the same encoder across multiple
operations. It handles the complex character mapping required for I2P network
compatibility while maintaining standard base64 semantics. The instance is
thread-safe and can be used concurrently across goroutines. Example: Used
internally by EncodeToString and DecodeString for consistent encoding behavior.

#### func  DecodeString

```go
func DecodeString(str string) ([]byte, error)
```
DecodeString converts I2P-compatible base64 strings back to their original
binary form. This function reverses the encoding process, taking base64 strings
that use I2P's alphabet and converting them back to the original byte data. It
validates input characters against the I2P alphabet and handles standard base64
padding requirements. Returns an error if the input contains invalid characters
or malformed padding. Example: DecodeString("SGVsbG8-") returns []byte{72, 101,
108, 108, 111}, nil (Hello decoded)

#### func  EncodeToString

```go
func EncodeToString(data []byte) string
```
EncodeToString converts arbitrary binary data to I2P-compatible base64 string
representation. This function takes raw byte data and produces a human-readable
string using I2P's modified base64 alphabet. The output is compatible with I2P
destination addresses, router identifiers, and other network protocol elements
that require base64 encoding. The encoding process applies standard base64
padding rules with '=' characters as needed. Example: EncodeToString([]byte{72,
101, 108, 108, 111}) returns "SGVsbG8-" (Hello in I2P base64)



base64 

github.com/go-i2p/common/base64

[go-i2p template file](/template.md)
