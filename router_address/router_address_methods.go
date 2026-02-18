// Package router_address implements the I2P RouterAddress common data structure
package router_address

import (
	"net"
	"strconv"
	"strings"

	"github.com/samber/oops"

	"github.com/go-i2p/common/data"
)

// Network implements net.Addr. It returns the transport type plus 4 or 6.
// If the IP version cannot be determined, only the transport type is returned.
func (ra *RouterAddress) Network() string {
	log.Debug("Getting network for RouterAddress")
	if ra.TransportType == nil {
		log.Warn("TransportType is nil in RouterAddress")
		return ""
	}
	str, err := ra.TransportType.Data()
	if err != nil {
		log.WithError(err).Error("Failed to get TransportType data")
		return ""
	}
	ipVer := ra.IPVersion()
	if ipVer == "" {
		return string(str)
	}
	network := string(str) + ipVer
	log.WithField("network", network).Debug("Retrieved network for RouterAddress")
	return network
}

// IPVersion returns "4" for IPv4 or "6" for IPv6.
// It first tries to infer the version from the host option's IP address.
// If no valid host IP is present, it falls back to checking the caps option suffix.
// Returns "" if the version cannot be determined.
func (ra *RouterAddress) IPVersion() string {
	log.Debug("Getting IP version for RouterAddress")
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
		log.Debug("IP version is IPv4 (from host)")
		return IPV4_VERSION_STRING
	}
	log.Debug("IP version is IPv6 (from host)")
	return IPV6_VERSION_STRING
}

// ipVersionFromCaps determines IP version from the caps option suffix.
// This is a Java router convention, not mandated by the I2P spec.
func (ra *RouterAddress) ipVersionFromCaps() string {
	caps := ra.CapsString()
	if caps == nil {
		return ""
	}
	str, err := caps.Data()
	if err != nil {
		return ""
	}
	if strings.HasSuffix(str, IPV6_SUFFIX) {
		log.Debug("IP version is IPv6 (from caps)")
		return IPV6_VERSION_STRING
	}
	log.Debug("IP version is IPv4 (from caps)")
	return IPV4_VERSION_STRING
}

// UDP checks if the RouterAddress is UDP-based
func (ra *RouterAddress) UDP() bool {
	log.Debug("Checking if RouterAddress is UDP")
	isUDP := strings.HasPrefix(strings.ToLower(ra.Network()), SSU_TRANSPORT_PREFIX)
	log.WithField("is_udp", isUDP).Debug("Checked if RouterAddress is UDP")
	return isUDP
}

// String implements net.Addr. It returns the transport style, host, port, and options.
// Safe to call on a zero-value or partially initialized RouterAddress.
func (ra *RouterAddress) String() string {
	log.Debug("Converting RouterAddress to string")
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
	appendOption(ra.StaticKeyString())
	appendOption(ra.InitializationVectorString())
	appendOption(ra.ProtocolVersionString())
	if ra.UDP() {
		for i := 0; i <= MAX_INTRODUCER_NUMBER; i++ {
			appendOption(ra.IntroducerHashString(i))
			appendOption(ra.IntroducerExpirationString(i))
			appendOption(ra.IntroducerTagString(i))
		}
	}
	str := strings.TrimSpace(strings.Join(rv, " "))
	log.WithField("router_address_string", str).Debug("Converted RouterAddress to string")
	return str
}

// Bytes returns the router address as a []byte.
// Returns nil if any required field is nil.
func (ra RouterAddress) Bytes() []byte {
	log.Debug("Converting RouterAddress to bytes")
	if ra.TransportCost == nil || ra.ExpirationDate == nil || ra.TransportOptions == nil {
		log.Warn("Cannot serialize RouterAddress with nil fields")
		return nil
	}
	buf := make([]byte, 0)
	buf = append(buf, ra.TransportCost.Bytes()...)
	buf = append(buf, ra.ExpirationDate.Bytes()...)
	buf = append(buf, ra.TransportType...)
	buf = append(buf, ra.TransportOptions.Data()...)
	log.WithField("bytes_length", len(buf)).Debug("Converted RouterAddress to bytes")
	return buf
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
	log.Debug("Getting host from RouterAddress")

	// Check if host key exists
	if !ra.CheckOption(HOST_OPTION_KEY) {
		log.Warn("RouterAddress missing required host key")
		return nil, oops.Errorf("RouterAddress missing required '%s' key in options mapping", HOST_OPTION_KEY)
	}

	host := ra.HostString()
	if host == nil {
		log.Warn("RouterAddress host option is nil")
		return nil, oops.Errorf("RouterAddress '%s' option is nil", HOST_OPTION_KEY)
	}

	hostBytes, err := host.Data()
	if err != nil {
		log.WithError(err).Warn("Failed to get host data")
		return nil, oops.Wrapf(err, "RouterAddress '%s' option data invalid", HOST_OPTION_KEY)
	}

	if len(hostBytes) == 0 {
		log.Warn("RouterAddress host option is empty")
		return nil, oops.Errorf("RouterAddress '%s' option is empty", HOST_OPTION_KEY)
	}

	ip := net.ParseIP(hostBytes)
	if ip == nil {
		log.WithField("hostBytes", string(hostBytes)).Error("Failed to parse IP address")
		return nil, oops.Errorf("RouterAddress '%s' option contains invalid IP address: %q", HOST_OPTION_KEY, string(hostBytes))
	}

	addr, err := net.ResolveIPAddr("", ip.String())
	if err != nil {
		log.WithError(err).WithField("ip", ip.String()).Error("Failed to resolve IP address")
		return nil, oops.Wrapf(err, "failed to resolve IP address %s", ip.String())
	}

	log.WithField("addr", addr).Debug("Retrieved host from RouterAddress")
	return addr, nil
}

// Port returns the port number as a string
func (ra RouterAddress) Port() (string, error) {
	log.Debug("Getting port from RouterAddress")

	// Check if port key exists
	if !ra.CheckOption(PORT_OPTION_KEY) {
		log.Warn("RouterAddress missing required port key")
		return "", oops.Errorf("RouterAddress missing required '%s' key in options mapping", PORT_OPTION_KEY)
	}

	port := ra.PortString()
	if port == nil {
		log.Warn("RouterAddress port option is nil")
		return "", oops.Errorf("RouterAddress '%s' option is nil", PORT_OPTION_KEY)
	}

	portBytes, err := port.Data()
	if err != nil {
		log.WithError(err).Warn("Failed to get port data")
		return "", oops.Wrapf(err, "RouterAddress '%s' option data invalid", PORT_OPTION_KEY)
	}

	if len(portBytes) == 0 {
		log.Warn("RouterAddress port option is empty")
		return "", oops.Errorf("RouterAddress '%s' option is empty", PORT_OPTION_KEY)
	}

	val, err := strconv.Atoi(portBytes)
	if err != nil {
		log.WithError(err).WithField("portBytes", string(portBytes)).Error("Failed to convert port to integer")
		return "", oops.Wrapf(err, "RouterAddress '%s' option is not a valid number: %q", PORT_OPTION_KEY, string(portBytes))
	}

	if val < 1 || val > 65535 {
		log.WithField("port", val).Error("Port number out of valid range")
		return "", oops.Errorf("RouterAddress '%s' option out of valid range (1-65535): %d", PORT_OPTION_KEY, val)
	}

	portStr := strconv.Itoa(val)
	log.WithField("port", portStr).Debug("Retrieved port from RouterAddress")
	return portStr, nil
}

// HasValidHost checks if the RouterAddress has a valid and usable host option.
// This is useful for defensive programming to skip invalid addresses gracefully.
// Returns true if the host option exists, is non-empty, and contains a valid IP address.
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

	ip := net.ParseIP(hostBytes)
	return ip != nil
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
// Uses I2PString.Data() to extract content without the length prefix.
func (ra RouterAddress) StaticKey() ([32]byte, error) {
	sk := ra.StaticKeyString()
	if sk == nil {
		return [32]byte{}, oops.Errorf("error: static key not found")
	}
	skData, err := sk.Data()
	if err != nil {
		return [32]byte{}, oops.Errorf("error: failed to read static key data: %v", err)
	}
	skBytes := []byte(skData)
	if len(skBytes) != STATIC_KEY_SIZE {
		return [32]byte{}, oops.Errorf("error: invalid static key length: %d, expected %d", len(skBytes), STATIC_KEY_SIZE)
	}
	var result [32]byte
	copy(result[:], skBytes)
	return result, nil
}

// InitializationVector returns the initialization vector as a 16-byte array.
// Uses I2PString.Data() to extract content without the length prefix.
func (ra RouterAddress) InitializationVector() ([16]byte, error) {
	iv := ra.InitializationVectorString()
	if iv == nil {
		return [16]byte{}, oops.Errorf("error: initialization vector not found")
	}
	ivData, err := iv.Data()
	if err != nil {
		return [16]byte{}, oops.Errorf("error: failed to read IV data: %v", err)
	}
	ivBytes := []byte(ivData)
	if len(ivBytes) != INITIALIZATION_VECTOR_SIZE {
		return [16]byte{}, oops.Errorf("error: invalid IV length: %d, expected %d", len(ivBytes), INITIALIZATION_VECTOR_SIZE)
	}
	var result [16]byte
	copy(result[:], ivBytes)
	return result, nil
}

// ProtocolVersion returns the protocol version as a string
func (ra RouterAddress) ProtocolVersion() (string, error) {
	return ra.ProtocolVersionString().Data()
}

// Options returns the options for this RouterAddress as an I2P Mapping.
func (ra RouterAddress) Options() data.Mapping {
	if ra.TransportOptions == nil {
		log.Warn("TransportOptions is nil in RouterAddress")
		return data.Mapping{}
	}
	return *ra.TransportOptions
}

// checkValid checks if the RouterAddress is empty or if it is too small to contain valid data.
func (ra RouterAddress) checkValid() (err error, exit bool) {
	if ra.TransportType == nil {
		return oops.Errorf("invalid router address: nil transport type"), true
	}
	if ra.TransportOptions == nil {
		return oops.Errorf("invalid router address: nil transport options"), true
	}
	return nil, false
}

// Equals compares two RouterAddress instances for equality.
// Two addresses are equal if they have the same cost, expiration, transport style, and options.
func (ra RouterAddress) Equals(other RouterAddress) bool {
	if ra.Cost() != other.Cost() {
		return false
	}
	raExp := ra.Expiration()
	otherExp := other.Expiration()
	if raExp != otherExp {
		return false
	}
	raBytes := ra.Bytes()
	otherBytes := other.Bytes()
	if raBytes == nil || otherBytes == nil {
		return raBytes == nil && otherBytes == nil
	}
	if len(raBytes) != len(otherBytes) {
		return false
	}
	for i := range raBytes {
		if raBytes[i] != otherBytes[i] {
			return false
		}
	}
	return true
}
