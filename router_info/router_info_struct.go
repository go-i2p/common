package router_info

import (
	"encoding/binary"
	"strconv"
	"strings"
	"time"

	"github.com/go-i2p/crypto/ed25519"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"

	"github.com/sirupsen/logrus"

	. "github.com/go-i2p/common/data"
	. "github.com/go-i2p/common/router_address"
	. "github.com/go-i2p/common/router_identity"
	. "github.com/go-i2p/common/signature"
)

/*
[RouterInfo]
Accurate for version 0.9.49

Description
Defines all of the data that a router wants to public for the network to see. The
RouterInfo is one of two structures stored in the network database (the other being
LeaseSet), and is keyed under the SHA256 of the contained RouterIdentity.

Contents
RouterIdentity followed by the Date, when the entry was published

+----+----+----+----+----+----+----+----+
| router_ident                          |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| published                             |
+----+----+----+----+----+----+----+----+
|size| RouterAddress 0                  |
+----+                                  +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| RouterAddress 1                       |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| RouterAddress ($size-1)               |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+-//-+----+----+----+
|psiz| options                          |
+----+----+----+----+-//-+----+----+----+
| signature                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+

router_ident :: RouterIdentity
                length -> >= 387 bytes

published :: Date
             length -> 8 bytes

size :: Integer
        length -> 1 byte
        The number of RouterAddresses to follow, 0-255

addresses :: [RouterAddress]
             length -> varies

peer_size :: Integer
             length -> 1 byte
             The number of peer Hashes to follow, 0-255, unused, always zero
             value -> 0

options :: Mapping

signature :: Signature
             length -> 40 bytes
*/

// RouterInfo is the represenation of an I2P RouterInfo.
//
// https://geti2p.net/spec/common-structures#routerinfo
type RouterInfo struct {
	router_identity *RouterIdentity
	published       *Date
	size            *Integer
	addresses       []*RouterAddress
	peer_size       *Integer
	options         *Mapping
	signature       *Signature
}

// NewRouterInfo creates a new RouterInfo with the specified parameters.
func NewRouterInfo(
	routerIdentity *RouterIdentity,
	publishedTime time.Time,
	addresses []*RouterAddress,
	options map[string]string,
	signingPrivateKey types.SigningPrivateKey,
	sigType int,
) (*RouterInfo, error) {
	log.Debug("Creating new RouterInfo")

	publishedDate, err := createPublishedDate(publishedTime)
	if err != nil {
		return nil, err
	}

	sizeInt, peerSizeInt, err := createSizeIntegers(addresses)
	if err != nil {
		return nil, err
	}

	mapping, err := convertOptionsToMapping(options)
	if err != nil {
		return nil, err
	}

	routerInfo := assembleRouterInfoWithoutSignature(routerIdentity, publishedDate, sizeInt, addresses, peerSizeInt, mapping)

	signer, err := createSignerFromPrivateKey(signingPrivateKey, sigType)
	if err != nil {
		return nil, err
	}

	signature, err := signRouterInfoData(routerInfo, signer, sigType)
	if err != nil {
		return nil, err
	}

	routerInfo.signature = signature

	log.WithFields(logrus.Fields{
		"router_identity": routerIdentity,
		"published":       publishedDate,
		"address_count":   len(addresses),
		"options":         options,
		"signature":       signature,
	}).Debug("Successfully created RouterInfo")

	return routerInfo, nil
}

// createPublishedDate converts a time.Time to an I2P Date structure.
func createPublishedDate(publishedTime time.Time) (*Date, error) {
	millis := publishedTime.UnixNano() / int64(time.Millisecond)
	dateBytes := make([]byte, DATE_SIZE)
	binary.BigEndian.PutUint64(dateBytes, uint64(millis))
	publishedDate, _, err := ReadDate(dateBytes)
	if err != nil {
		log.WithError(err).Error("Failed to create Published Date")
		return nil, oops.Errorf("failed to create published date: %v", err)
	}
	return &publishedDate, nil
}

// createSizeIntegers creates the size and peer size integer fields for RouterInfo.
func createSizeIntegers(addresses []*RouterAddress) (*Integer, *Integer, error) {
	sizeInt, err := NewIntegerFromInt(len(addresses), 1)
	if err != nil {
		log.WithError(err).Error("Failed to create Size Integer")
		return nil, nil, oops.Errorf("failed to create size integer: %v", err)
	}

	peerSizeInt, err := NewIntegerFromInt(0, 1)
	if err != nil {
		log.WithError(err).Error("Failed to create PeerSize Integer")
		return nil, nil, oops.Errorf("failed to create peer size integer: %v", err)
	}

	return sizeInt, peerSizeInt, nil
}

// convertOptionsToMapping converts a Go map to an I2P Mapping structure.
func convertOptionsToMapping(options map[string]string) (*Mapping, error) {
	mapping, err := GoMapToMapping(options)
	if err != nil {
		log.WithError(err).Error("Failed to convert options map to Mapping")
		return nil, oops.Errorf("failed to convert options to mapping: %v", err)
	}
	return mapping, nil
}

// assembleRouterInfoWithoutSignature creates a RouterInfo structure without the signature field.
func assembleRouterInfoWithoutSignature(
	routerIdentity *RouterIdentity,
	publishedDate *Date,
	sizeInt *Integer,
	addresses []*RouterAddress,
	peerSizeInt *Integer,
	mapping *Mapping,
) *RouterInfo {
	return &RouterInfo{
		router_identity: routerIdentity,
		published:       publishedDate,
		size:            sizeInt,
		addresses:       addresses,
		peer_size:       peerSizeInt,
		options:         mapping,
		signature:       nil, // To be set after signing
	}
}

// createSignerFromPrivateKey validates the private key and creates an appropriate signer.
func createSignerFromPrivateKey(signingPrivateKey types.SigningPrivateKey, sigType int) (types.Signer, error) {
	if signingPrivateKey == nil {
		return nil, oops.Errorf("signing private key is nil")
	}

	var signer types.Signer
	var err error

	switch sigType {
	case signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519:
		ed25519Key, ok := signingPrivateKey.(*ed25519.Ed25519PrivateKey)
		if !ok {
			return nil, oops.Errorf("expected *Ed25519PrivateKey but got %T", signingPrivateKey)
		}
		if len(*ed25519Key) != 64 {
			return nil, oops.Errorf("invalid Ed25519 private key size: got %d, want 64", len(*ed25519Key))
		}
		signer, err = ed25519Key.NewSigner()
	default:
		return nil, oops.Errorf("unsupported signature type: %d", sigType)
	}

	if err != nil {
		log.WithError(err).Error("Failed to create signer")
		return nil, oops.Errorf("failed to create signer: %v", err)
	}

	return signer, nil
}

// signRouterInfoData serializes RouterInfo data and creates a signature.
func signRouterInfoData(routerInfo *RouterInfo, signer types.Signer, sigType int) (*Signature, error) {
	dataBytes := routerInfo.serializeWithoutSignature()

	signatureBytes, err := signer.Sign(dataBytes)
	if err != nil {
		log.WithError(err).Error("Failed to sign RouterInfo data")
		return nil, oops.Errorf("failed to sign data: %v", err)
	}

	sig, _, err := ReadSignature(signatureBytes, sigType)
	if err != nil {
		log.WithError(err).Error("Failed to create Signature from signature bytes")
		return nil, oops.Errorf("failed to create signature: %v", err)
	}

	return &sig, nil
}

// Bytes returns the RouterInfo as a []byte suitable for writing to a stream.
func (router_info RouterInfo) Bytes() (bytes []byte, err error) {
	log.Debug("Converting RouterInfo to bytes")
	bytes = append(bytes, router_info.router_identity.Bytes()...)
	bytes = append(bytes, router_info.published.Bytes()...)
	bytes = append(bytes, router_info.size.Bytes()...)
	for _, router_address := range router_info.addresses {
		bytes = append(bytes, router_address.Bytes()...)
	}
	bytes = append(bytes, router_info.peer_size.Bytes()...)
	bytes = append(bytes, router_info.options.Data()...)
	bytes = append(bytes, []byte(*router_info.signature)...)
	log.WithField("bytes_length", len(bytes)).Debug("Converted RouterInfo to bytes")
	return bytes, err
}

// String returns a string representation of the RouterInfo.
func (router_info RouterInfo) String() string {
	log.Debug("Converting RouterInfo to string")
	str := "Certificate: " + bytesToString(router_info.router_identity.Bytes()) + "\n"
	str += "Published: " + bytesToString(router_info.published.Bytes()) + "\n"
	str += "Addresses:" + bytesToString(router_info.size.Bytes()) + "\n"
	for index, router_address := range router_info.addresses {
		str += "Address " + strconv.Itoa(index) + ": " + router_address.String() + "\n"
	}
	str += "Peer Size: " + bytesToString(router_info.peer_size.Bytes()) + "\n"
	str += "Options: " + bytesToString(router_info.options.Data()) + "\n"
	str += "Signature: " + bytesToString([]byte(*router_info.signature)) + "\n"
	log.WithField("string_length", len(str)).Debug("Converted RouterInfo to string")
	return str
}

// RouterIdentity returns the router identity as *RouterIdentity.
func (router_info *RouterInfo) RouterIdentity() *RouterIdentity {
	return router_info.router_identity
}

// IdentHash returns the identity hash (sha256 sum) for this RouterInfo.
func (router_info *RouterInfo) IdentHash() Hash {
	log.Debug("Calculating IdentHash for RouterInfo")
	// Hash the complete RouterIdentity bytes as per I2P specification
	data := router_info.RouterIdentity().Bytes()
	hash := HashData(data)
	log.WithField("hash", hash).Debug("Calculated IdentHash for RouterInfo")
	return hash
}

// Published returns the date this RouterInfo was published as an I2P Date.
func (router_info *RouterInfo) Published() *Date {
	return router_info.published
}

// RouterAddressCount returns the count of RouterAddress in this RouterInfo as a Go integer.
func (router_info *RouterInfo) RouterAddressCount() int {
	count := router_info.size.Int()
	log.WithField("count", count).Debug("Retrieved RouterAddressCount from RouterInfo")
	return count
}

// RouterAddresses returns all RouterAddresses for this RouterInfo as []*RouterAddress.
func (router_info *RouterInfo) RouterAddresses() []*RouterAddress {
	log.WithField("address_count", len(router_info.addresses)).Debug("Retrieved RouterAddresses from RouterInfo")
	return router_info.addresses
}

// PeerSize returns the peer size as a Go integer.
func (router_info *RouterInfo) PeerSize() int {
	// Peer size is unused according to I2P spec (always 0):
	// https://geti2p.net/spec/common-structures#routeraddress
	// But we return the actual field value to maintain API contract
	return router_info.peer_size.Int()
}

// Options returns the options for this RouterInfo as an I2P Mapping.
func (router_info RouterInfo) Options() (mapping Mapping) {
	return *router_info.options
}

// Signature returns the signature for this RouterInfo as an I2P Signature.
func (router_info RouterInfo) Signature() (signature Signature) {
	return *router_info.signature
}

// Network implements net.Addr
func (router_info RouterInfo) Network() string {
	return "i2p"
}

// AddAddress adds a RouterAddress to this RouterInfo.
func (router_info *RouterInfo) AddAddress(address *RouterAddress) {
	router_info.addresses = append(router_info.addresses, address)
}

// RouterCapabilities returns the capabilities string for this RouterInfo.
func (router_info *RouterInfo) RouterCapabilities() string {
	log.Debug("Retrieving RouterCapabilities")
	str, err := ToI2PString("caps")
	if err != nil {
		log.WithError(err).Error("Failed to create I2PString for 'caps'")
		return ""
	}
	// return string(router_info.options.Values().Get(str))
	caps := string(router_info.options.Values().Get(str))
	log.WithField("capabilities", caps).Debug("Retrieved RouterCapabilities")
	return caps
}

// RouterVersion returns the version string for this RouterInfo.
func (router_info *RouterInfo) RouterVersion() string {
	log.Debug("Retrieving RouterVersion")
	str, err := ToI2PString("router.version")
	if err != nil {
		log.WithError(err).Error("Failed to create I2PString for 'router.version'")
		return ""
	}
	// return string(router_info.options.Values().Get(str))
	version := string(router_info.options.Values().Get(str))
	log.WithField("version", version).Debug("Retrieved RouterVersion")
	return version
}

// GoodVersion checks if the RouterInfo version is acceptable.
func (router_info *RouterInfo) GoodVersion() bool {
	log.Debug("Checking if RouterVersion is good")
	version := router_info.RouterVersion()
	v := strings.Split(version, ".")
	if len(v) != 3 {
		log.WithField("version", version).Warn("Invalid version format")
		return false
	}
	if v[0] == "0" {
		if v[1] == "9" {
			val, _ := strconv.Atoi(v[2])
			if val >= MIN_GOOD_VERSION && val <= MAX_GOOD_VERSION {
				return true
			}
		}
	}
	log.WithField("version", version).Warn("Version not in good range")
	return false
}

// UnCongested checks if the RouterInfo indicates the router is not congested.
func (router_info *RouterInfo) UnCongested() bool {
	log.Debug("Checking if RouterInfo is uncongested")
	caps := router_info.RouterCapabilities()
	if strings.Contains(caps, "K") {
		log.WithField("reason", "K capability").Warn("RouterInfo is congested")
		return false
	}
	if strings.Contains(caps, "G") {
		log.WithField("reason", "G capability").Warn("RouterInfo is congested")
		return false
	}
	if strings.Contains(caps, "E") {
		log.WithField("reason", "E capability").Warn("RouterInfo is congested")
		return false
	}
	log.Debug("RouterInfo is uncongested")
	return true
}

// Reachable checks if the RouterInfo indicates the router is reachable.
func (router_info *RouterInfo) Reachable() bool {
	log.Debug("Checking if RouterInfo is reachable")
	caps := router_info.RouterCapabilities()
	if strings.Contains(caps, "U") {
		log.WithField("reason", "U capability").Debug("RouterInfo is unreachable")
		return false
	}
	// return strings.Contains(caps, "R")
	reachable := strings.Contains(caps, "R")
	log.WithFields(logrus.Fields{
		"reachable": reachable,
		"reason":    "R capability",
	}).Debug("Checked RouterInfo reachability")
	return reachable
}

// serializeWithoutSignature serializes the RouterInfo up to (but not including) the signature.
func (ri *RouterInfo) serializeWithoutSignature() []byte {
	var bytes []byte
	// Serialize RouterIdentity
	bytes = append(bytes, ri.router_identity.Bytes()...)

	// Serialize Published Date
	bytes = append(bytes, ri.published.Bytes()...)

	// Serialize Size
	bytes = append(bytes, ri.size.Bytes()...)

	// Serialize Addresses
	for _, addr := range ri.addresses {
		bytes = append(bytes, addr.Bytes()...)
	}

	// Serialize PeerSize (always zero)
	bytes = append(bytes, ri.peer_size.Bytes()...)

	// Serialize Options
	bytes = append(bytes, ri.options.Data()...)

	return bytes
}

// ReadRouterInfo returns RouterInfo from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadRouterInfo(bytes []byte) (info RouterInfo, remainder []byte, err error) {
	log.WithField("input_length", len(bytes)).Debug("Reading RouterInfo from bytes")

	// Parse core RouterInfo fields
	info, remainder, err = parseRouterInfoCore(bytes)
	if err != nil {
		return
	}

	// Parse router addresses
	info.addresses, remainder, err = parseRouterAddresses(info.size, remainder)
	if err != nil {
		return
	}

	// Parse peer size and options
	info.peer_size, info.options, remainder, err = parsePeerSizeAndOptions(remainder)
	if err != nil {
		return
	}

	// Parse signature
	info.signature, remainder, err = parseRouterInfoSignature(info.router_identity, remainder)
	if err != nil {
		return
	}

	log.WithFields(logrus.Fields{
		"router_identity":  info.router_identity,
		"published":        info.published,
		"address_count":    len(info.addresses),
		"remainder_length": len(remainder),
	}).Debug("Successfully read RouterInfo")

	return
}

// parseRouterInfoCore reads the RouterIdentity, published date, and address count from bytes.
func parseRouterInfoCore(bytes []byte) (info RouterInfo, remainder []byte, err error) {
	info.router_identity, remainder, err = ReadRouterIdentity(bytes)
	if err != nil {
		log.WithFields(logrus.Fields{
			"at":           "(RouterInfo) parseRouterInfoCore",
			"data_len":     len(bytes),
			"required_len": ROUTER_INFO_MIN_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing router info")
		return
	}

	info.published, remainder, err = NewDate(remainder)
	if err != nil {
		log.WithFields(logrus.Fields{
			"at":           "(RouterInfo) parseRouterInfoCore",
			"data_len":     len(remainder),
			"required_len": DATE_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing router info")
		return
	}

	info.size, remainder, err = NewInteger(remainder, 1)
	if err != nil {
		log.WithFields(logrus.Fields{
			"at":           "(RouterInfo) parseRouterInfoCore",
			"data_len":     len(remainder),
			"required_len": info.size.Int(),
			"reason":       "read error",
		}).Error("error parsing router info size")
		return
	}

	return
}

// parseRouterAddresses reads the specified number of RouterAddress structures from bytes.
func parseRouterAddresses(size *Integer, remainder []byte) ([]*RouterAddress, []byte, error) {
	var addresses []*RouterAddress

	for i := 0; i < size.Int(); i++ {
		address, more, err := ReadRouterAddress(remainder)
		remainder = more
		if err != nil {
			log.WithFields(logrus.Fields{
				"at":       "(RouterInfo) parseRouterAddresses",
				"data_len": len(remainder),
				"reason":   "not enough data",
			}).Error("error parsing router address")
			return addresses, remainder, err
		}
		addresses = append(addresses, &address)
	}

	return addresses, remainder, nil
}

// parsePeerSizeAndOptions reads the peer size and options mapping from bytes.
func parsePeerSizeAndOptions(remainder []byte) (*Integer, *Mapping, []byte, error) {
	peer_size, remainder, err := NewInteger(remainder, 1)
	if err != nil {
		log.WithError(err).Error("Failed to read PeerSize")
		return nil, nil, remainder, err
	}

	var errs []error
	options, remainder, errs := NewMapping(remainder)
	if len(errs) != 0 {
		// Check if errors are just warnings about extra data beyond mapping length
		hasNonWarningErrors := false
		for _, e := range errs {
			if !strings.Contains(e.Error(), "warning parsing mapping: data exists beyond length of mapping") {
				hasNonWarningErrors = true
				break
			}
		}

		if hasNonWarningErrors {
			log.WithFields(logrus.Fields{
				"at":       "(RouterInfo) parsePeerSizeAndOptions",
				"data_len": len(remainder),
				"reason":   "not enough data",
			}).Error("error parsing router info")
			estring := ""
			for _, e := range errs {
				estring += e.Error() + " "
			}
			return peer_size, options, remainder, errs[0]
		} else {
			// Just warnings about extra data - log but continue parsing
			log.WithFields(logrus.Fields{
				"at":     "(RouterInfo) parsePeerSizeAndOptions",
				"reason": "extra data beyond mapping length",
			}).Warn("mapping format violation")
		}
	}

	return peer_size, options, remainder, nil
}

// parseRouterInfoSignature extracts signature type from certificate and reads the signature.
func parseRouterInfoSignature(router_identity *RouterIdentity, remainder []byte) (*Signature, []byte, error) {
	// Add debug logging for certificate inspection
	cert := router_identity.Certificate()
	log.WithFields(logrus.Fields{
		"at":            "(RouterInfo) parseRouterInfoSignature",
		"cert_type":     cert.Type(),
		"cert_length":   cert.Length(),
		"remainder_len": len(remainder),
	}).Debug("Processing certificate")

	sigType, err := certificate.GetSignatureTypeFromCertificate(cert)
	if err != nil {
		log.WithError(err).Error("Failed to get signature type from certificate")
		return nil, remainder, oops.Errorf("certificate signature type error: %v", err)
	}

	// Enhanced signature type validation
	if sigType <= SIGNATURE_TYPE_RSA_SHA256_2048 || sigType > SIGNATURE_TYPE_REDDSA_SHA512_ED25519 {
		log.WithFields(logrus.Fields{
			"sigType": sigType,
			"cert":    cert,
		}).Error("Invalid signature type detected")
		return nil, remainder, oops.Errorf("invalid signature type: %d", sigType)
	}

	log.WithFields(logrus.Fields{
		"sigType": sigType,
	}).Debug("Got sigType")

	signature, remainder, err := NewSignature(remainder, sigType)
	if err != nil {
		log.WithFields(logrus.Fields{
			"at":       "(RouterInfo) parseRouterInfoSignature",
			"data_len": len(remainder),
			"reason":   "not enough data",
		}).Error("error parsing router info")
		return nil, remainder, oops.Errorf("error parsing router info: not enough data to read signature")
	}

	return signature, remainder, nil
}
