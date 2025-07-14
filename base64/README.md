# base64
--
    import "github.com/go-i2p/common/base64"

![base64.svg](base64.svg)

Package base64 implements utilities for encoding and decoding text using I2P's
### alphabet

This package provides I2P-specific base64 encoding/decoding functionality using
RFC 4648 with "/" replaced with "~", and "+" replaced with "-".


Package base64 constants

Package base64 utilities and encoding instances

## Usage

```go
const I2PEncodeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~"
```
I2PEncodeAlphabet is the base64 encoding used throughout I2P. RFC 4648 with "/"
replaced with "~", and "+" replaced with "-".

```go
var I2PEncoding *b64.Encoding = b64.NewEncoding(I2PEncodeAlphabet)
```
I2PEncoding is the standard base64 encoding used through I2P.

#### func  DecodeString

```go
func DecodeString(str string) ([]byte, error)
```
DecodeString decodes base64 string to []byte using I2P encoding.

#### func  EncodeToString

```go
func EncodeToString(data []byte) string
```
EncodeToString encodes data to string using I2P base64 encoding.



base64 

github.com/go-i2p/common/base64

[go-i2p template file](/template.md)
