// Package router_address implements the I2P RouterAddress common data structure
package router_address

import (
	"bytes"
	"net"
	"strconv"
	"strings"

	"github.com/samber/oops"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
)

// Network implements net.Addr. It returns the transport type plus 4 or 6.
// If the IP version cannot be determined, only the transport type is returned.
func (ra *RouterAddress) Network() string {
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.Network"}).Debug("Getting network for RouterAddress")
	if ra.TransportType == nil {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.Network"}).Warn("TransportType is nil in RouterAddress")
		return ""
	}
	str, err := ra.TransportType.Data()
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.Network"}).WithError(err).Error("Failed to get TransportType data")
		return ""
	}
	ipVer := ra.IPVersion()
	if ipVer == "" {
		return string(str)
	}
	network := string(str) + ipVer
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.Network", "network": network}).Debug("Retrieved network for RouterAddress")
	return network
}

// IPVersion returns "4" for IPv4 or "6" for IPv6.
// It first tries to infer the version from the host option's IP address.
// If no valid host IP is present, it falls back to checking the caps option suffix.
// Returns "" if the version cannot be determined.
func (ra *RouterAddress) IPVersion() string {
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.IPVersion"}).Debug("Getting IP version for RouterAddress")
	// Primary: infer from host address
	if ver := ra.ipVersionFromHost(); ver != "" {
		return ver
	}
	// Fallback: infer from caps suffix (Java router convention)
	return ra.ipVersionFromCaps()
}

// ipVersionFromHost determines IP version by parsing the host option value.
func (ra *RouterAddress) ipVersionFromHost() string {
	host := ra.HostString()
	if host == nil {
		return ""
	}
	hostData, err := host.Data()
	if err != nil || len(hostData) == 0 {
		return ""
	}
	ip := net.ParseIP(hostData)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.ipVersionFromHost"}).Debug("IP version is IPv4 (from host)")
		return IPV4_VERSION_STRING
	}
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.ipVersionFromHost"}).Debug("IP version is IPv6 (from host)")
	return IPV6_VERSION_STRING
}

// ipVersionFromCaps determines IP version from the caps option suffix.
// This is a Java router convention, not mandated by the I2P spec.
// Caps strings ending in "4" indicate IPv4; those ending in "6" indicate IPv6.
// Returns "" if the caps string is empty, missing, or has no recognized IP suffix.
func (ra *RouterAddress) ipVersionFromCaps() string {
	caps := ra.CapsString()
	if caps == nil {
		return ""
	}
	str, err := caps.Data()
	if err != nil {
		return ""
	}
	if len(str) == 0 {
		return ""
	}
	if strings.HasSuffix(str, IPV6_SUFFIX) {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.ipVersionFromCaps"}).Debug("IP version is IPv6 (from caps)")
		return IPV6_VERSION_STRING
	}
	if strings.HasSuffix(str, IPV4_VERSION_STRING) {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.ipVersionFromCaps"}).Debug("IP version is IPv4 (from caps)")
		return IPV4_VERSION_STRING
	}
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.ipVersionFromCaps"}).Debug("IP version cannot be determined from caps")
	return ""
}

// UDP checks if the RouterAddress is UDP-based
func (ra *RouterAddress) UDP() bool {
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.UDP"}).Debug("Checking if RouterAddress is UDP")
	isUDP := strings.HasPrefix(strings.ToLower(ra.Network()), SSU_TRANSPORT_PREFIX)
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.UDP", "is_udp": isUDP}).Debug("Checked if RouterAddress is UDP")
	return isUDP
}

// IsNTCP2 returns true if the transport style is exactly "NTCP2".
func (ra *RouterAddress) IsNTCP2() bool {
	if ra.TransportType == nil {
		return false
	}
	style, err := ra.TransportType.Data()
	if err != nil {
		return false
	}
	return style == NTCP2_TRANSPORT_STYLE
}

// IsSSU2 returns true if the transport style is exactly "SSU2".
func (ra *RouterAddress) IsSSU2() bool {
	if ra.TransportType == nil {
		return false
	}
	style, err := ra.TransportType.Data()
	if err != nil {
		return false
	}
	return style == SSU2_TRANSPORT_STYLE
}

// String implements net.Addr. It returns a compact summary suitable for
// logging: transport style, host, and port. Cryptographic material (static
// key, IV, introducer data) is deliberately excluded to prevent accidental
// exposure in logs or error messages. Use GoString() for debug-level detail.
func (ra *RouterAddress) String() string {
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.String"}).Debug("Converting RouterAddress to string")
	if ra == nil {
		return ""
	}
	var rv []string
	appendOption := func(s data.I2PString) {
		if s != nil {
			if d, err := s.Data(); err == nil && len(d) > 0 {
				rv = append(rv, d)
			}
		}
	}
	appendOption(ra.TransportStyle())
	appendOption(ra.HostString())
	appendOption(ra.PortString())
	str := strings.TrimSpace(strings.Join(rv, " "))
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.String", "router_address_string": str}).Debug("Converted RouterAddress to string")
	return str
}

// Bytes returns the router address as a []byte.
// Returns nil if any required field is nil or empty; use Serialize for
// explicit error reporting.
func (ra RouterAddress) Bytes() []byte {
	b, _ := ra.Serialize()
	return b
}

// Serialize returns the wire encoding of the RouterAddress together with any
// serialization error.  Callers that need to distinguish a valid empty result
// from a serialization failure should prefer this method over Bytes.
func (ra RouterAddress) Serialize() ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.Serialize"}).Debug("Serializing RouterAddress")
	if ra.TransportCost == nil {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.Serialize"}).Warn("Cannot serialize RouterAddress: TransportCost is nil")
		return nil, oops.Errorf("%w", ErrMissingTransportCost)
	}
	if ra.ExpirationDate == nil {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.Serialize"}).Warn("Cannot serialize RouterAddress: ExpirationDate is nil")
		return nil, oops.Errorf("%w", ErrMissingExpirationDate)
	}
	if len(ra.TransportType) == 0 {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.Serialize"}).Warn("Cannot serialize RouterAddress: TransportType is nil or empty")
		return nil, oops.Errorf("%w", ErrMissingTransportType)
	}
	// Verify the I2PString content is non-empty (catches {0x00} — a valid I2PString
	// encoding that declares zero content bytes).
	if content, err := ra.TransportType.Data(); err != nil || len(content) == 0 {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.Serialize"}).Warn("Cannot serialize RouterAddress: TransportType content is empty")
		return nil, oops.Errorf("%w", ErrEmptyTransportStyle)
	}
	if ra.TransportOptions == nil {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.Serialize"}).Warn("Cannot serialize RouterAddress: TransportOptions is nil")
		return nil, oops.Errorf("%w", ErrMissingTransportOptions)
	}
	var buf []byte
	buf = append(buf, ra.TransportCost.Bytes()...)
	buf = append(buf, ra.ExpirationDate.Bytes()...)
	buf = append(buf, ra.TransportType...)
	buf = append(buf, ra.TransportOptions.Data()...)
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.Serialize", "bytes_length": len(buf)}).Debug("Serialized RouterAddress")
	return buf, nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
// It delegates to Serialize().
func (ra RouterAddress) MarshalBinary() ([]byte, error) {
	return ra.Serialize()
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
// It delegates to ReadRouterAddress, discarding any remainder bytes.
func (ra *RouterAddress) UnmarshalBinary(data []byte) error {
	parsed, _, err := ReadRouterAddress(data)
	if err != nil {
		return err
	}
	*ra = parsed
	return nil
}

// Cost returns the cost for this RouterAddress as a Go integer.
// Returns 0 if TransportCost is nil.
func (ra RouterAddress) Cost() int {
	if ra.TransportCost == nil {
		return 0
	}
	return ra.TransportCost.Int()
}

// Expiration returns the expiration for this RouterAddress as an I2P Date.
// Returns a zero Date if ExpirationDate is nil.
func (ra RouterAddress) Expiration() data.Date {
	if ra.ExpirationDate == nil {
		return data.Date{}
	}
	return *ra.ExpirationDate
}

// TransportStyle returns the transport style for this RouterAddress as an I2PString.
func (ra RouterAddress) TransportStyle() data.I2PString {
	return ra.TransportType
}

// GetOption returns the value of the option specified by the key
func (ra RouterAddress) GetOption(key data.I2PString) data.I2PString {
	return ra.Options().Values().Get(key)
}

// HasOption checks if a given option key exists
func (ra RouterAddress) HasOption(key data.I2PString) bool {
	opt := ra.GetOption(key)
	return opt != nil
}

// CheckOption checks if an option exists using a string key
func (ra RouterAddress) CheckOption(key string) bool {
	keyv, _ := data.ToI2PString(key)
	return ra.HasOption(keyv)
}

// HostString returns the host option as an I2PString
func (ra RouterAddress) HostString() data.I2PString {
	host, _ := data.ToI2PString(HOST_OPTION_KEY)
	return ra.GetOption(host)
}

// PortString returns the port option as an I2PString
func (ra RouterAddress) PortString() data.I2PString {
	port, _ := data.ToI2PString(PORT_OPTION_KEY)
	return ra.GetOption(port)
}

// CapsString returns the caps option as an I2PString
func (ra RouterAddress) CapsString() data.I2PString {
	caps, _ := data.ToI2PString(CAPS_OPTION_KEY)
	return ra.GetOption(caps)
}

// StaticKeyString returns the static key option as an I2PString
func (ra RouterAddress) StaticKeyString() data.I2PString {
	sk, _ := data.ToI2PString(STATIC_KEY_OPTION_KEY)
	return ra.GetOption(sk)
}

// InitializationVectorString returns the initialization vector option as an I2PString
func (ra RouterAddress) InitializationVectorString() data.I2PString {
	iv, _ := data.ToI2PString(INITIALIZATION_VECTOR_OPTION_KEY)
	return ra.GetOption(iv)
}

// ProtocolVersionString returns the protocol version option as an I2PString
func (ra RouterAddress) ProtocolVersionString() data.I2PString {
	v, _ := data.ToI2PString(PROTOCOL_VERSION_OPTION_KEY)
	return ra.GetOption(v)
}

// IntroducerHashString returns the introducer hash option for the specified number
func (ra RouterAddress) IntroducerHashString(num int) data.I2PString {
	if num >= MIN_INTRODUCER_NUMBER && num <= MAX_INTRODUCER_NUMBER {
		val := strconv.Itoa(num)
		v, _ := data.ToI2PString(INTRODUCER_HASH_PREFIX + val)
		return ra.GetOption(v)
	}
	v, _ := data.ToI2PString(INTRODUCER_HASH_PREFIX + strconv.Itoa(DEFAULT_INTRODUCER_NUMBER))
	return ra.GetOption(v)
}

// IntroducerExpirationString returns the introducer expiration option for the specified number
func (ra RouterAddress) IntroducerExpirationString(num int) data.I2PString {
	if num >= MIN_INTRODUCER_NUMBER && num <= MAX_INTRODUCER_NUMBER {
		val := strconv.Itoa(num)
		v, _ := data.ToI2PString(INTRODUCER_EXPIRATION_PREFIX + val)
		return ra.GetOption(v)
	}
	v, _ := data.ToI2PString(INTRODUCER_EXPIRATION_PREFIX + strconv.Itoa(DEFAULT_INTRODUCER_NUMBER))
	return ra.GetOption(v)
}

// IntroducerTagString returns the introducer tag option for the specified number
func (ra RouterAddress) IntroducerTagString(num int) data.I2PString {
	if num >= MIN_INTRODUCER_NUMBER && num <= MAX_INTRODUCER_NUMBER {
		val := strconv.Itoa(num)
		v, _ := data.ToI2PString(INTRODUCER_TAG_PREFIX + val)
		return ra.GetOption(v)
	}
	v, _ := data.ToI2PString(INTRODUCER_TAG_PREFIX + strconv.Itoa(DEFAULT_INTRODUCER_NUMBER))
	return ra.GetOption(v)
}

// Host returns the host address as a net.Addr.
// Only IP addresses are accepted; hostnames are rejected as a security measure.
// Note: the I2P spec allows hostnames in the host option, but this implementation
// intentionally rejects them to prevent DNS-based deanonymization attacks.
func (ra RouterAddress) Host() (net.Addr, error) {
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.Host"}).Debug("Getting host from RouterAddress")

	hostBytes, err := extractOptionBytes(ra, HOST_OPTION_KEY, ra.HostString())
	if err != nil {
		return nil, err
	}

	return resolveHostIP(hostBytes)
}

// extractOptionBytes retrieves and validates the byte content of a named
// RouterAddress option. Returns an error if the option is missing, nil, or empty.
func extractOptionBytes(ra RouterAddress, key string, option data.I2PString) (string, error) {
	if !ra.CheckOption(key) {
		// Debug: many legitimate address types omit optional keys (e.g. host for
		// introducer-only addresses). Callers decide severity from the returned error.
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "extractOptionBytes"}).Debug("RouterAddress option not present: " + key)
		return "", oops.Errorf("RouterAddress missing required '%s' key in options mapping", key)
	}
	if option == nil {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "extractOptionBytes"}).Warn("RouterAddress " + key + " option is nil")
		return "", oops.Errorf("RouterAddress '%s' option is nil", key)
	}
	content, err := option.Data()
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "extractOptionBytes"}).WithError(err).Warn("Failed to get " + key + " data")
		return "", oops.Wrapf(err, "RouterAddress '%s' option data invalid", key)
	}
	if len(content) == 0 {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "extractOptionBytes"}).Warn("RouterAddress " + key + " option is empty")
		return "", oops.Errorf("RouterAddress '%s' option is empty", key)
	}
	return content, nil
}

// HostAddr is a net.Addr implementation wrapping a hostname string.
// It is returned by Host() when the host option contains a valid hostname
// rather than an IP literal, per the I2P spec which permits host names.
type HostAddr struct {
	hostname string
}

// Network implements net.Addr; returns "host" for non-IP hostnames.
func (h HostAddr) Network() string { return "host" }

// String implements net.Addr; returns the raw hostname.
func (h HostAddr) String() string { return h.hostname }

// resolveHostIP parses a host string as an IP address or hostname and returns
// a net.Addr.  Per the I2P spec the host option allows "an IPv4 or IPv6
// address or host name", so valid hostnames are wrapped in a HostAddr.
func resolveHostIP(hostBytes string) (net.Addr, error) {
	// Try IP literal first.
	ip := net.ParseIP(hostBytes)
	if ip != nil {
		addr, err := net.ResolveIPAddr("", ip.String())
		if err != nil {
			log.WithFields(logger.Fields{"pkg": "router_address", "func": "resolveHostIP", "ip": ip.String()}).WithError(err).Error("Failed to resolve IP address")
			return nil, oops.Wrapf(err, "failed to resolve IP address %s", ip.String())
		}
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "resolveHostIP", "addr": addr}).Debug("Retrieved host from RouterAddress (IP)")
		return addr, nil
	}
	// Not an IP literal — check for valid hostname format (RFC 1123 character set).
	if !isValidHostFormat(hostBytes) {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "resolveHostIP", "hostBytes": hostBytes}).Error("Failed to parse host as IP or valid hostname")
		return nil, oops.Errorf("RouterAddress '%s' option contains invalid host: %q", HOST_OPTION_KEY, hostBytes)
	}
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "resolveHostIP", "hostname": hostBytes}).Debug("Retrieved host from RouterAddress (hostname)")
	return HostAddr{hostname: hostBytes}, nil
}

// isValidHostFormat returns true when s is a syntactically valid hostname per
// RFC 1123 (letters, digits, hyphens, and dots only; non-empty; ≤253 chars).
func isValidHostFormat(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// Port returns the port number as a string
func (ra RouterAddress) Port() (string, error) {
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.Port"}).Debug("Getting port from RouterAddress")

	portBytes, err := extractOptionBytes(ra, PORT_OPTION_KEY, ra.PortString())
	if err != nil {
		return "", err
	}

	return validatePortValue(portBytes)
}

// validatePortValue parses a port string, checks it is a valid integer in
// the range 1-65535, and returns it as a string.
func validatePortValue(portBytes string) (string, error) {
	val, err := strconv.Atoi(portBytes)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "validatePortValue", "portBytes": portBytes}).WithError(err).Error("Failed to convert port to integer")
		return "", oops.Wrapf(err, "RouterAddress '%s' option is not a valid number: %q", PORT_OPTION_KEY, portBytes)
	}

	if val < 1 || val > 65535 {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "validatePortValue", "port": val}).Error("Port number out of valid range")
		return "", oops.Errorf("RouterAddress '%s' option out of valid range (1-65535): %d", PORT_OPTION_KEY, val)
	}

	portStr := strconv.Itoa(val)
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "validatePortValue", "port": portStr}).Debug("Retrieved port from RouterAddress")
	return portStr, nil
}

// HasValidHost checks if the RouterAddress has a valid and usable host option.
// Per the I2P spec the host option may contain an IPv4/IPv6 address or a
// hostname; this method returns true for all three valid forms.
func (ra RouterAddress) HasValidHost() bool {
	if !ra.CheckOption(HOST_OPTION_KEY) {
		return false
	}

	host := ra.HostString()
	if host == nil {
		return false
	}

	hostBytes, err := host.Data()
	if err != nil || len(hostBytes) == 0 {
		return false
	}

	// Valid if it's a parseable IP literal or a syntactically valid hostname.
	return net.ParseIP(hostBytes) != nil || isValidHostFormat(hostBytes)
}

// HasValidPort checks if the RouterAddress has a valid and usable port option.
// This is useful for defensive programming to skip invalid addresses gracefully.
// Returns true if the port option exists, is non-empty, is a valid number, and is in range 1-65535.
func (ra RouterAddress) HasValidPort() bool {
	if !ra.CheckOption(PORT_OPTION_KEY) {
		return false
	}

	port := ra.PortString()
	if port == nil {
		return false
	}

	portBytes, err := port.Data()
	if err != nil || len(portBytes) == 0 {
		return false
	}

	val, err := strconv.Atoi(portBytes)
	if err != nil {
		return false
	}

	return val >= 1 && val <= 65535
}

// StaticKey returns the static key as a 32-byte array.
// Per the NTCP2 specification, the "s" option value is base64-encoded.
// This method attempts base64 decode first (I2P alphabet), then falls back
// to treating the value as raw bytes for backward compatibility.
func (ra RouterAddress) StaticKey() ([32]byte, error) {
	sk := ra.StaticKeyString()
	if sk == nil {
		return [32]byte{}, oops.Errorf("%w", ErrMissingStaticKey)
	}
	skData, err := sk.Data()
	if err != nil {
		return [32]byte{}, oops.Errorf("failed to read static key data: %w", err)
	}
	skBytes, err := decodeOptionValue(skData, STATIC_KEY_SIZE)
	if err != nil {
		return [32]byte{}, oops.Errorf("%w: got %d bytes, expected %d", ErrInvalidStaticKey, len(skBytes), STATIC_KEY_SIZE)
	}
	var result [32]byte
	copy(result[:], skBytes)
	return result, nil
}

// InitializationVector returns the initialization vector as a 16-byte array.
// Per the NTCP2 specification, the "i" option value is base64-encoded.
// This method attempts base64 decode first (I2P alphabet), then falls back
// to treating the value as raw bytes for backward compatibility.
func (ra RouterAddress) InitializationVector() ([16]byte, error) {
	iv := ra.InitializationVectorString()
	if iv == nil {
		return [16]byte{}, oops.Errorf("%w", ErrMissingInitializationVector)
	}
	ivData, err := iv.Data()
	if err != nil {
		return [16]byte{}, oops.Errorf("failed to read IV data: %w", err)
	}
	ivBytes, err := decodeOptionValue(ivData, INITIALIZATION_VECTOR_SIZE)
	if err != nil {
		return [16]byte{}, oops.Errorf("%w: got %d bytes, expected %d", ErrInvalidInitializationVector, len(ivBytes), INITIALIZATION_VECTOR_SIZE)
	}
	var result [16]byte
	copy(result[:], ivBytes)
	return result, nil
}

// ProtocolVersion returns the protocol version as a string.
// Returns ("", error) if the "v" option is not set.
func (ra RouterAddress) ProtocolVersion() (string, error) {
	pvs := ra.ProtocolVersionString()
	if pvs == nil {
		return "", oops.Errorf("protocol version option %q not set", PROTOCOL_VERSION_OPTION_KEY)
	}
	return pvs.Data()
}

// Options returns the options for this RouterAddress as an I2P Mapping.
func (ra RouterAddress) Options() data.Mapping {
	if ra.TransportOptions == nil {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "RouterAddress.Options"}).Warn("TransportOptions is nil in RouterAddress")
		return data.Mapping{}
	}
	return *ra.TransportOptions
}

// Equals compares two RouterAddress instances for equality.
// Two addresses are equal if they have the same cost, expiration, transport style, and options.
// Returns false if either address cannot be serialized (nil fields).
func (ra RouterAddress) Equals(other RouterAddress) bool {
	aBytes := ra.Bytes()
	bBytes := other.Bytes()
	// If either address fails serialization, they are not meaningfully comparable.
	if aBytes == nil || bBytes == nil {
		return false
	}
	return bytes.Equal(aBytes, bBytes)
}

// decodeOptionValue attempts to decode a string option value as I2P base64.
// If the base64-decoded result has the expected length, it is returned.
// Otherwise, the raw bytes of the string are checked for the expected length.
// This provides backward compatibility for callers that store raw bytes.
func decodeOptionValue(val string, expectedLen int) ([]byte, error) {
	// If raw bytes already match expected length, use them directly.
	rawBytes := []byte(val)
	if len(rawBytes) == expectedLen {
		return rawBytes, nil
	}
	// Try I2P base64 decode.
	decoded, err := i2pbase64.I2PEncoding.DecodeString(val)
	if err == nil && len(decoded) == expectedLen {
		return decoded, nil
	}
	// Neither raw nor base64 matched the expected length.
	return rawBytes, oops.Errorf("option value has wrong length: %d (raw) or decode failed", len(rawBytes))
}

// HasNonZeroExpiration returns true if the ExpirationDate field contains
// a non-zero value. Per the I2P spec (0.9.12+), routers MUST set the
// expiration field to all zeros. A non-zero value indicates the remote
// router is not following the spec.
func (ra RouterAddress) HasNonZeroExpiration() bool {
	if ra.ExpirationDate == nil {
		return false
	}
	for _, b := range ra.ExpirationDate {
		if b != 0 {
			return true
		}
	}
	return false
}

// GoString returns a detailed, labeled representation of the RouterAddress
// suitable for debugging with fmt.Sprintf("%#v"). Unlike String() (which
// implements net.Addr with a compact format), GoString includes field labels.
func (ra RouterAddress) GoString() string {
	if ra.TransportType == nil {
		return "RouterAddress{<invalid: nil transport type>}"
	}
	var sb strings.Builder
	sb.WriteString("RouterAddress{")
	appendTransportType(&sb, ra)
	appendCostField(&sb, ra)
	appendOptionalField(&sb, ra.HostString(), "host")
	appendOptionalField(&sb, ra.PortString(), "port")
	appendOptionalField(&sb, ra.ProtocolVersionString(), "v")
	sb.WriteString("}")
	return sb.String()
}

// appendTransportType writes the transport type label to the string builder.
func appendTransportType(sb *strings.Builder, ra RouterAddress) {
	if ts, err := ra.TransportType.Data(); err == nil {
		sb.WriteString("type=")
		sb.WriteString(ts)
	}
}

// appendCostField writes the cost label to the string builder.
func appendCostField(sb *strings.Builder, ra RouterAddress) {
	sb.WriteString(", cost=")
	sb.WriteString(strconv.Itoa(ra.Cost()))
}

// appendOptionalField writes a labeled option value to the string builder if
// the option is present and non-empty.
func appendOptionalField(sb *strings.Builder, opt data.I2PString, label string) {
	if opt == nil {
		return
	}
	val, err := opt.Data()
	if err != nil || len(val) == 0 {
		return
	}
	sb.WriteString(", ")
	sb.WriteString(label)
	sb.WriteString("=")
	sb.WriteString(val)
}

// SetOption sets or replaces a transport option in the RouterAddress.
// Both key and value are provided as Go strings and converted to I2PStrings.
// If TransportOptions is nil, a new Mapping is created.
//
// For setting multiple options at once, prefer SetOptions to avoid
// rebuilding the mapping on every call.
func (ra *RouterAddress) SetOption(key, value string) error {
	if ra == nil {
		return oops.Errorf("cannot set option on nil RouterAddress")
	}

	opts := extractOptionsMap(ra)
	opts[key] = value

	newMapping, err := data.GoMapToMapping(opts)
	if err != nil {
		return oops.Wrapf(err, "failed to create mapping with option %q=%q", key, value)
	}
	ra.TransportOptions = newMapping
	return nil
}

// SetOptions sets or replaces multiple transport options in a single call.
// This is more efficient than calling SetOption in a loop because the
// mapping is rebuilt only once.
func (ra *RouterAddress) SetOptions(opts map[string]string) error {
	if ra == nil {
		return oops.Errorf("cannot set options on nil RouterAddress")
	}

	existing := extractOptionsMap(ra)
	for k, v := range opts {
		existing[k] = v
	}

	newMapping, err := data.GoMapToMapping(existing)
	if err != nil {
		return oops.Wrapf(err, "failed to create mapping with batch options")
	}
	ra.TransportOptions = newMapping
	return nil
}

// RemoveOption removes a transport option by key. Returns nil if the key
// was not present (idempotent). Returns an error only if the mapping
// rebuild fails.
func (ra *RouterAddress) RemoveOption(key string) error {
	if ra == nil {
		return oops.Errorf("cannot remove option from nil RouterAddress")
	}

	opts := extractOptionsMap(ra)
	delete(opts, key)

	newMapping, err := data.GoMapToMapping(opts)
	if err != nil {
		return oops.Wrapf(err, "failed to rebuild mapping after removing %q", key)
	}
	ra.TransportOptions = newMapping
	return nil
}

// extractOptionsMap converts existing transport options to a Go map for modification.
func extractOptionsMap(ra *RouterAddress) map[string]string {
	opts := make(map[string]string)
	if ra.TransportOptions != nil {
		for _, pair := range ra.Options().Values() {
			k, kErr := pair[0].Data()
			v, vErr := pair[1].Data()
			if kErr == nil && vErr == nil {
				opts[k] = v
			}
		}
	}
	return opts
}
