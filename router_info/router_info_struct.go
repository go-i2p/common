package router_info

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-i2p/crypto/ed25519"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"

	"github.com/go-i2p/logger"
)

/*
[RouterInfo]
Accurate for version 0.9.67

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

options :: data.Mapping

signature :: Signature
             length -> 40 bytes or as specified in router_ident's key certificate
*/

// RouterInfo is the represenation of an I2P RouterInfo.
//
// https://geti2p.net/spec/common-structures#routerinfo
type RouterInfo struct {
	router_identity *router_identity.RouterIdentity
	published       *data.Date
	size            *data.Integer
	addresses       []*router_address.RouterAddress
	peer_size       *data.Integer
	options         *data.Mapping
	signature       *signature.Signature
}

// NewRouterInfo creates a new RouterInfo with the specified parameters.
func NewRouterInfo(
	routerIdentity *router_identity.RouterIdentity,
	publishedTime time.Time,
	addresses []*router_address.RouterAddress,
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

	log.WithFields(logger.Fields{
		"router_identity": routerIdentity,
		"published":       publishedDate,
		"address_count":   len(addresses),
		"options":         options,
		"signature":       signature,
	}).Debug("Successfully created RouterInfo")

	return routerInfo, nil
}

// createPublishedDate converts a time.Time to an I2P Date structure.
func createPublishedDate(publishedTime time.Time) (*data.Date, error) {
	millis := publishedTime.UnixNano() / int64(time.Millisecond)
	dateBytes := make([]byte, data.DATE_SIZE)
	binary.BigEndian.PutUint64(dateBytes, uint64(millis))
	publishedDate, _, err := data.ReadDate(dateBytes)
	if err != nil {
		log.WithError(err).Error("Failed to create Published Date")
		return nil, oops.Errorf("failed to create published date: %v", err)
	}
	return &publishedDate, nil
}

// createSizeIntegers creates the size and peer size integer fields for RouterInfo.
func createSizeIntegers(addresses []*router_address.RouterAddress) (*data.Integer, *data.Integer, error) {
	sizeInt, err := data.NewIntegerFromInt(len(addresses), 1)
	if err != nil {
		log.WithError(err).Error("Failed to create Size Integer")
		return nil, nil, oops.Errorf("failed to create size integer: %v", err)
	}

	peerSizeInt, err := data.NewIntegerFromInt(0, 1)
	if err != nil {
		log.WithError(err).Error("Failed to create PeerSize Integer")
		return nil, nil, oops.Errorf("failed to create peer size integer: %v", err)
	}

	return sizeInt, peerSizeInt, nil
}

// convertOptionsToMapping converts a Go map to an I2P data.Mapping structure.
func convertOptionsToMapping(options map[string]string) (*data.Mapping, error) {
	mapping, err := data.GoMapToMapping(options)
	if err != nil {
		log.WithError(err).Error("Failed to convert options map to data.Mapping")
		return nil, oops.Errorf("failed to convert options to mapping: %v", err)
	}
	return mapping, nil
}

// assembleRouterInfoWithoutSignature creates a RouterInfo structure without the signature field.
func assembleRouterInfoWithoutSignature(
	routerIdentity *router_identity.RouterIdentity,
	publishedDate *data.Date,
	sizeInt *data.Integer,
	addresses []*router_address.RouterAddress,
	peerSizeInt *data.Integer,
	mapping *data.Mapping,
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
		if len(*ed25519Key) != ED25519_PRIVATE_KEY_SIZE {
			return nil, oops.Errorf("invalid Ed25519 private key size: got %d, want %d", len(*ed25519Key), ED25519_PRIVATE_KEY_SIZE)
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
func signRouterInfoData(routerInfo *RouterInfo, signer types.Signer, sigType int) (*signature.Signature, error) {
	dataBytes, err := routerInfo.serializeWithoutSignature()
	if err != nil {
		log.WithError(err).Error("Failed to serialize RouterInfo for signing")
		return nil, oops.Errorf("failed to serialize data: %v", err)
	}

	signatureBytes, err := signer.Sign(dataBytes)
	if err != nil {
		log.WithError(err).Error("Failed to sign RouterInfo data")
		return nil, oops.Errorf("failed to sign data: %v", err)
	}

	sig, _, err := signature.ReadSignature(signatureBytes, sigType)
	if err != nil {
		log.WithError(err).Error("Failed to create Signature from signature bytes")
		return nil, oops.Errorf("failed to create signature: %v", err)
	}

	return &sig, nil
}

// Bytes returns the RouterInfo as a []byte suitable for writing to a stream.
// Returns an error if any required field is nil.
func (router_info RouterInfo) Bytes() ([]byte, error) {
	log.Debug("Converting RouterInfo to bytes")
	if err := validateBytesPrerequisites(&router_info); err != nil {
		return nil, err
	}
	bytes, err := serializeRouterInfoFields(&router_info)
	if err != nil {
		return nil, err
	}
	log.WithField("bytes_length", len(bytes)).Debug("Converted RouterInfo to bytes")
	return bytes, nil
}

// validateBytesPrerequisites checks that all required RouterInfo fields are non-nil
// before serialization.
func validateBytesPrerequisites(ri *RouterInfo) error {
	if ri.router_identity == nil {
		return oops.Errorf("cannot serialize RouterInfo: router_identity is nil")
	}
	if ri.published == nil {
		return oops.Errorf("cannot serialize RouterInfo: published is nil")
	}
	if ri.size == nil {
		return oops.Errorf("cannot serialize RouterInfo: size is nil")
	}
	if ri.peer_size == nil {
		return oops.Errorf("cannot serialize RouterInfo: peer_size is nil")
	}
	if ri.options == nil {
		return oops.Errorf("cannot serialize RouterInfo: options is nil")
	}
	if ri.signature == nil {
		return oops.Errorf("cannot serialize RouterInfo: signature is nil")
	}
	return nil
}

// serializeRouterInfoFields serializes all RouterInfo fields into a byte slice.
func serializeRouterInfoFields(ri *RouterInfo) ([]byte, error) {
	identityBytes, err := ri.router_identity.Bytes()
	if err != nil {
		return nil, err
	}
	var bytes []byte
	bytes = append(bytes, identityBytes...)
	bytes = append(bytes, ri.published.Bytes()...)
	bytes = append(bytes, ri.size.Bytes()...)
	for _, addr := range ri.addresses {
		bytes = append(bytes, addr.Bytes()...)
	}
	bytes = append(bytes, ri.peer_size.Bytes()...)
	bytes = append(bytes, ri.options.Data()...)
	bytes = append(bytes, ri.signature.Bytes()...)
	return bytes, nil
}

// String returns a string representation of the RouterInfo.
// Returns a placeholder string if any required field is nil.
func (router_info RouterInfo) String() string {
	log.Debug("Converting RouterInfo to string")
	if router_info.router_identity == nil || router_info.published == nil ||
		router_info.size == nil || router_info.peer_size == nil ||
		router_info.options == nil || router_info.signature == nil {
		return "RouterInfo{<uninitialized>}"
	}
	identityBytes, err := router_info.router_identity.Bytes()
	if err != nil {
		return "RouterInfo{<error serializing identity>}"
	}
	str := "RouterIdentity: " + bytesToString(identityBytes) + "\n"
	str += "Published: " + bytesToString(router_info.published.Bytes()) + "\n"
	str += "Addresses:" + bytesToString(router_info.size.Bytes()) + "\n"
	for index, addr := range router_info.addresses {
		str += "Address " + strconv.Itoa(index) + ": " + addr.String() + "\n"
	}
	str += "Peer Size: " + bytesToString(router_info.peer_size.Bytes()) + "\n"
	str += "Options: " + bytesToString(router_info.options.Data()) + "\n"
	str += "Signature: " + bytesToString(router_info.signature.Bytes()) + "\n"
	log.WithField("string_length", len(str)).Debug("Converted RouterInfo to string")
	return str
}

// RouterIdentity returns the router identity as *RouterIdentity.
func (router_info *RouterInfo) RouterIdentity() *router_identity.RouterIdentity {
	return router_info.router_identity
}

// IdentHash returns the identity hash (sha256 sum) for this RouterInfo.
func (router_info *RouterInfo) IdentHash() (data.Hash, error) {
	log.Debug("Calculating IdentHash for RouterInfo")

	// Check if router_identity is nil (e.g., uninitialized RouterInfo in tests)
	if router_info.router_identity == nil {
		log.Debug("RouterInfo has nil router_identity, cannot calculate IdentHash")
		return data.Hash{}, fmt.Errorf("router_identity is nil")
	}

	// Hash the complete RouterIdentity bytes as per I2P specification
	identityData, err := router_info.router_identity.Bytes()
	if err != nil {
		return data.Hash{}, err
	}
	hash := data.HashData(identityData)
	log.WithField("hash", hash).Debug("Calculated IdentHash for RouterInfo")
	return hash, nil
}

// Published returns the date this RouterInfo was published as an I2P Date.
func (router_info *RouterInfo) Published() *data.Date {
	return router_info.published
}

// RouterAddressCount returns the count of RouterAddress in this RouterInfo as a Go integer.
// Returns 0 if the size field is nil (e.g., uninitialized or failed-parse RouterInfo).
func (router_info *RouterInfo) RouterAddressCount() int {
	if router_info.size == nil {
		return 0
	}
	count := router_info.size.Int()
	log.WithField("count", count).Debug("Retrieved RouterAddressCount from RouterInfo")
	return count
}

// RouterAddresses returns all RouterAddresses for this RouterInfo as []*router_address.RouterAddress.
func (router_info *RouterInfo) RouterAddresses() []*router_address.RouterAddress {
	log.WithField("address_count", len(router_info.addresses)).Debug("Retrieved RouterAddresses from RouterInfo")
	return router_info.addresses
}

// PeerSize returns the peer size as a Go integer.
// Returns 0 if the peer_size field is nil (e.g., uninitialized or failed-parse RouterInfo).
func (router_info *RouterInfo) PeerSize() int {
	// Peer size is unused according to I2P spec (always 0):
	// https://geti2p.net/spec/common-structures#routerinfo
	// But we return the actual field value to maintain API contract
	if router_info.peer_size == nil {
		return 0
	}
	return router_info.peer_size.Int()
}

// Options returns the options for this RouterInfo as an I2P data.Mapping.
// Returns an empty Mapping if the options field is nil.
func (router_info RouterInfo) Options() (mapping data.Mapping) {
	if router_info.options == nil {
		return data.Mapping{}
	}
	return *router_info.options
}

// Signature returns the signature for this RouterInfo as an I2P Signature.
// Returns a zero-value Signature if the signature field is nil.
func (router_info RouterInfo) Signature() (sig signature.Signature) {
	if router_info.signature == nil {
		return signature.Signature{}
	}
	return *router_info.signature
}

// Network implements net.Addr
func (router_info RouterInfo) Network() string {
	return I2P_NETWORK_NAME
}

// AddAddress adds a RouterAddress to this RouterInfo and updates the size field.
// Returns an error if the address count would exceed 255 (max for 1-byte Integer).
func (router_info *RouterInfo) AddAddress(address *router_address.RouterAddress) error {
	newCount := len(router_info.addresses) + 1
	newSize, err := data.NewIntegerFromInt(newCount, 1)
	if err != nil {
		return oops.Errorf("cannot add address: count %d exceeds 1-byte integer max: %v", newCount, err)
	}
	router_info.addresses = append(router_info.addresses, address)
	router_info.size = newSize
	return nil
}

// RouterCapabilities returns the capabilities string for this RouterInfo.
func (router_info *RouterInfo) RouterCapabilities() string {
	log.Debug("Retrieving RouterCapabilities")
	str, err := data.ToI2PString("caps")
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
	str, err := data.ToI2PString("router.version")
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
func (router_info *RouterInfo) GoodVersion() (bool, error) {
	log.Debug("Checking if RouterVersion is good")
	version := router_info.RouterVersion()

	versionParts, err := parseAndValidateVersionString(version)
	if err != nil {
		return false, err
	}

	majorVersion, err := validateMajorVersion(versionParts[0], version)
	if err != nil {
		return false, err
	}

	minorVersion, err := validateMinorVersion(versionParts[1], majorVersion, version)
	if err != nil {
		return false, err
	}

	isValid, err := validatePatchVersionRange(versionParts[2], minorVersion, version)
	if err != nil {
		return false, err
	}

	if isValid {
		log.WithField("version", version).Debug("Version is in good range")
		return true, nil
	}

	log.WithField("version", version).Warn("Version not in good range")
	return false, oops.Errorf("version not in good range: %s", version)
}

// parseAndValidateVersionString splits version string and validates format.
func parseAndValidateVersionString(version string) ([]string, error) {
	v := strings.Split(version, ".")
	if len(v) != 3 {
		log.WithField("version", version).Warn("Invalid version format", v)
		return nil, oops.Errorf("invalid version format: %s", version)
	}

	v[0] = cleanString(v[0])
	v[1] = cleanString(v[1])
	v[2] = cleanString(v[2])
	log.WithField("version", version).Debugf("Checking version: '%s''%s''%s'", v[0], v[1], v[2])

	return v, nil
}

// validateMajorVersion parses and validates the major version component.
func validateMajorVersion(majorStr, version string) (int, error) {
	pos0, err := strconv.Atoi(majorStr)
	if err != nil {
		log.WithError(err).Error("Failed to parse version component 0")
		return 0, oops.Errorf("Failed to parse version component 0: '%s' '%s'", majorStr, err)
	}

	if pos0 != 0 {
		log.WithField("version", version).Debug("Invalid version at position 0:", majorStr)
		return 0, oops.Errorf("Invalid version at position 0: %s", majorStr)
	}

	return pos0, nil
}

// validateMinorVersion parses and validates the minor version component.
func validateMinorVersion(minorStr string, majorVersion int, version string) (int, error) {
	if majorVersion != 0 {
		return 0, oops.Errorf("Invalid major version: %d", majorVersion)
	}

	pos1, err := strconv.Atoi(minorStr)
	if err != nil {
		log.WithError(err).Error("Failed to parse version component 1")
		return 0, oops.Errorf("Failed to parse version component 1: '%s'", minorStr)
	}

	if pos1 != 9 {
		log.WithField("version", version).Debug("Invalid version at position 1:", minorStr)
		return 0, oops.Errorf("Invalid version at position 0: %s", minorStr)
	}

	return pos1, nil
}

// validatePatchVersionRange parses and validates the patch version is within acceptable range.
func validatePatchVersionRange(patchStr string, minorVersion int, version string) (bool, error) {
	if minorVersion != 9 {
		return false, oops.Errorf("Invalid minor version: %d", minorVersion)
	}

	val, err := strconv.Atoi(patchStr)
	if err != nil {
		log.WithError(err).Error("Failed to parse version component 2")
		return false, oops.Errorf("Failed to parse version component 2: '%s'", patchStr)
	}

	return val >= MIN_GOOD_VERSION && val <= MAX_GOOD_VERSION, nil
}

// UnCongested checks if the RouterInfo indicates the router is not congested.
// Per the I2P spec, congestion indicators are:
//   - D: medium congestion
//   - E: high congestion
//   - G: rejecting tunnels
//
// Note: K is a bandwidth class ("Under 12 KBps"), NOT a congestion indicator.
func (router_info *RouterInfo) UnCongested() bool {
	log.Debug("Checking if RouterInfo is uncongested")
	caps := router_info.RouterCapabilities()
	if strings.Contains(caps, "D") {
		log.WithField("reason", "D capability (medium congestion)").Warn("RouterInfo is congested")
		return false
	}
	if strings.Contains(caps, "E") {
		log.WithField("reason", "E capability (high congestion)").Warn("RouterInfo is congested")
		return false
	}
	if strings.Contains(caps, "G") {
		log.WithField("reason", "G capability (rejecting tunnels)").Warn("RouterInfo is congested")
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
	log.WithFields(logger.Fields{
		"reachable": reachable,
		"reason":    "R capability",
	}).Debug("Checked RouterInfo reachability")
	return reachable
}

// serializeWithoutSignature serializes the RouterInfo up to (but not including) the signature.
func (ri *RouterInfo) serializeWithoutSignature() ([]byte, error) {
	var bytes []byte
	// Serialize RouterIdentity
	identityBytes, err := ri.router_identity.Bytes()
	if err != nil {
		return nil, err
	}
	bytes = append(bytes, identityBytes...)

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

	return bytes, nil
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

	log.WithFields(logger.Fields{
		"router_identity":  info.router_identity,
		"published":        info.published,
		"address_count":    len(info.addresses),
		"remainder_length": len(remainder),
	}).Debug("Successfully read RouterInfo")

	return
}

// parseRouterInfoCore reads the RouterIdentity, published date, and address count from bytes.
func parseRouterInfoCore(bytes []byte) (info RouterInfo, remainder []byte, err error) {
	info.router_identity, remainder, err = router_identity.ReadRouterIdentity(bytes)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":           "(RouterInfo) parseRouterInfoCore",
			"data_len":     len(bytes),
			"required_len": ROUTER_INFO_MIN_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing router info")
		return
	}

	info.published, remainder, err = data.NewDate(remainder)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":           "(RouterInfo) parseRouterInfoCore",
			"data_len":     len(remainder),
			"required_len": data.DATE_SIZE,
			"reason":       "not enough data",
		}).Error("error parsing router info")
		return
	}

	info.size, remainder, err = data.NewInteger(remainder, 1)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":           "(RouterInfo) parseRouterInfoCore",
			"data_len":     len(remainder),
			"required_len": 1,
			"reason":       "read error",
		}).Error("error parsing router info size")
		return
	}

	return
}

// parseRouterAddresses reads the specified number of RouterAddress structures from bytes.
func parseRouterAddresses(size *data.Integer, remainder []byte) ([]*router_address.RouterAddress, []byte, error) {
	var addresses []*router_address.RouterAddress

	for i := 0; i < size.Int(); i++ {
		address, more, err := router_address.ReadRouterAddress(remainder)
		remainder = more
		if err != nil {
			log.WithFields(logger.Fields{
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
func parsePeerSizeAndOptions(remainder []byte) (*data.Integer, *data.Mapping, []byte, error) {
	peer_size, remainder, err := parsePeerSizeFromBytes(remainder)
	if err != nil {
		return nil, nil, remainder, err
	}

	options, remainder, err := parseOptionsMapping(remainder)
	if err != nil {
		return peer_size, options, remainder, err
	}

	return peer_size, options, remainder, nil
}

// parsePeerSizeFromBytes extracts the peer size integer from the byte data.
func parsePeerSizeFromBytes(remainder []byte) (*data.Integer, []byte, error) {
	peer_size, remainder, err := data.NewInteger(remainder, 1)
	if err != nil {
		log.WithError(err).Error("Failed to read PeerSize")
		return nil, remainder, err
	}
	if peer_size.Int() != 0 {
		log.WithFields(logger.Fields{
			"peer_size": peer_size.Int(),
		}).Warn("Spec violation: peer_size should always be zero")
	}
	return peer_size, remainder, nil
}

// parseOptionsMapping extracts the options mapping and handles error categorization.
func parseOptionsMapping(remainder []byte) (*data.Mapping, []byte, error) {
	var errs []error
	options, remainder, errs := data.NewMapping(remainder)
	if len(errs) == 0 {
		return options, remainder, nil
	}

	if hasCriticalMappingErrors(errs) {
		logCriticalMappingErrors(remainder, errs)
		return options, remainder, errs[0]
	}

	logMappingWarnings()
	return options, remainder, nil
}

// hasCriticalMappingErrors checks if any errors are critical (not just warnings).
func hasCriticalMappingErrors(errs []error) bool {
	for _, e := range errs {
		if !strings.Contains(e.Error(), "warning parsing mapping: data exists beyond length of mapping") {
			return true
		}
	}
	return false
}

// logCriticalMappingErrors logs critical mapping parsing errors.
func logCriticalMappingErrors(remainder []byte, errs []error) {
	errMsgs := make([]string, len(errs))
	for i, e := range errs {
		errMsgs[i] = e.Error()
	}
	log.WithFields(logger.Fields{
		"at":       "(RouterInfo) parsePeerSizeAndOptions",
		"data_len": len(remainder),
		"errors":   strings.Join(errMsgs, "; "),
		"reason":   "mapping parse errors",
	}).Error("error parsing router info")
}

// logMappingWarnings logs warnings about extra data beyond mapping length.
func logMappingWarnings() {
	log.WithFields(logger.Fields{
		"at":     "(RouterInfo) parsePeerSizeAndOptions",
		"reason": "extra data beyond mapping length",
	}).Warn("mapping format violation")
}

// parseRouterInfoSignature extracts signature type from certificate and reads the signature.
// getCertificateTypeFromIdentity extracts and validates the certificate type from router identity.
// Returns the certificate type, certificate data, and any error encountered.
func getCertificateTypeFromIdentity(router_identity *router_identity.RouterIdentity) (int, []byte, error) {
	cert := router_identity.Certificate()
	kind, err := cert.Type()
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "getCertificateTypeFromIdentity",
			"reason": "invalid certificate type",
		}).Error("error parsing router info signature")
		return 0, nil, oops.Errorf("invalid certificate type: %v", err)
	}

	certData, err := cert.Data()
	if err != nil {
		log.WithError(err).Error("Failed to read Certificate Data")
		return 0, nil, err
	}

	log.WithFields(logger.Fields{
		"at":          "getCertificateTypeFromIdentity",
		"cert_type":   kind,
		"cert_length": len(certData),
	}).Debug("Processing certificate")

	return kind, certData, nil
}

// getSignatureTypeFromCert extracts the signature type from a certificate.
// Returns the signature type and any error encountered.
func getSignatureTypeFromCert(cert *certificate.Certificate) (int, error) {
	sigType, err := certificate.GetSignatureTypeFromCertificate(*cert)
	if err != nil {
		log.WithError(err).Error("Failed to get signature type from certificate")
		return 0, oops.Errorf("certificate signature type error: %v", err)
	}
	return sigType, nil
}

// validateSignatureType validates that the signature type is a recognized I2P
// signature type. Accepts types 0-11, reserved GOST types 9-10, reserved MLDSA
// types 12-20, and experimental types 65280-65534. Returns error for completely
// unknown types. This delegates to the signature package's SignatureSize for
// authoritative type validation.
func validateSignatureType(sigType int, cert *certificate.Certificate) error {
	// Use the signature package as single source of truth for type validation
	_, err := signature.SignatureSize(sigType)
	if err != nil {
		log.WithFields(logger.Fields{
			"sigType": sigType,
		}).Error("Invalid signature type detected")
		return oops.Errorf("invalid signature type: %d: %v", sigType, err)
	}
	if sigType <= signature.SIGNATURE_TYPE_RSA_SHA256_2048 {
		log.WithFields(logger.Fields{
			"sigType": sigType,
		}).Warn("Deprecated signature type (types 0-4 are deprecated as of 0.9.58)")
	}
	log.WithFields(logger.Fields{
		"sigType": sigType,
	}).Debug("Got sigType")
	return nil
}

// parseSignatureData parses the signature from data using the specified signature type.
// Returns the parsed signature, remaining data, and any error encountered.
func parseSignatureData(data []byte, sigType int) (*signature.Signature, []byte, error) {
	sig, remainder, err := signature.NewSignature(data, sigType)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":       "parseSignatureData",
			"data_len": len(data),
			"reason":   "not enough data",
		}).Error("error parsing router info")
		return nil, remainder, oops.Errorf("error parsing router info: not enough data to read signature")
	}
	return sig, remainder, nil
}

func parseRouterInfoSignature(ri *router_identity.RouterIdentity, remainder []byte) (*signature.Signature, []byte, error) {
	certType, _, err := getCertificateTypeFromIdentity(ri)
	if err != nil {
		return nil, remainder, err
	}

	var sigType int
	if certType == certificate.CERT_KEY {
		cert := ri.Certificate()
		sigType, err = getSignatureTypeFromCert(cert)
		if err != nil {
			return nil, remainder, err
		}
	} else {
		// NULL certificate (type 0) and other non-KEY types default to DSA_SHA1
		sigType = signature.SIGNATURE_TYPE_DSA_SHA1
		log.WithFields(logger.Fields{
			"cert_type": certType,
			"sig_type":  sigType,
		}).Debug("Non-KEY certificate, defaulting to DSA_SHA1 signature type")
	}

	if err := validateSignatureType(sigType, ri.Certificate()); err != nil {
		return nil, remainder, err
	}

	return parseSignatureData(remainder, sigType)
}
