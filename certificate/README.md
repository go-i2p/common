# certificate
--
    import "github.com/go-i2p/go-i2p/lib/common/certificate"

![certificate.svg](certificate.svg)



## Usage

```go
const (
	CERT_NULL = iota
	CERT_HASHCASH
	CERT_HIDDEN
	CERT_SIGNED
	CERT_MULTIPLE
	CERT_KEY
)
```
Certificate Types

```go
const CERT_MIN_SIZE = 3
```
CERT_MIN_SIZE is the minimum size of a valid Certificate in []byte 1 byte for
type 2 bytes for payload length

#### func  GetSignatureTypeFromCertificate

```go
func GetSignatureTypeFromCertificate(cert Certificate) (int, error)
```

#### type Certificate

```go
type Certificate struct {
}
```

Certificate is the representation of an I2P Certificate.

https://geti2p.net/spec/common-structures#certificate

#### func  NewCertificate

```go
func NewCertificate() *Certificate
```
NewCertificate creates a new Certificate with default NULL type

#### func  NewCertificateDeux

```go
func NewCertificateDeux(certType int, payload []byte) (*Certificate, error)
```

#### func  NewCertificateWithType

```go
func NewCertificateWithType(certType uint8, payload []byte) (*Certificate, error)
```
NewCertificateWithType creates a new Certificate with specified type and payload

#### func  ReadCertificate

```go
func ReadCertificate(data []byte) (certificate Certificate, remainder []byte, err error)
```
ReadCertificate creates a Certificate from []byte and returns any ExcessBytes at
the end of the input. returns err if the certificate could not be read.

#### func (*Certificate) Bytes

```go
func (c *Certificate) Bytes() []byte
```
Bytes returns the entire certificate in []byte form, trims payload to specified
length.

#### func (*Certificate) Data

```go
func (c *Certificate) Data() (data []byte)
```
Data returns the payload of a Certificate, payload is trimmed to the specified
length.

#### func (*Certificate) ExcessBytes

```go
func (c *Certificate) ExcessBytes() []byte
```
ExcessBytes returns the excess bytes in a certificate found after the specified
payload length.

#### func (*Certificate) Length

```go
func (c *Certificate) Length() (length int)
```
Length returns the payload length of a Certificate.

#### func (*Certificate) RawBytes

```go
func (c *Certificate) RawBytes() []byte
```
RawBytes returns the entire certificate in []byte form, includes excess payload
data.

#### func (*Certificate) Type

```go
func (c *Certificate) Type() (cert_type int)
```
Type returns the Certificate type specified in the first byte of the
Certificate,



certificate 

github.com/go-i2p/go-i2p/lib/common/certificate

[go-i2p template file](/template.md)
