// Package router_address implements the I2P RouterAddress common data structure
package router_address

import (
	"net"
	"strconv"
	"strings"

	"github.com/samber/oops"

	"github.com/go-i2p/common/data"
)

// Network implements net.Addr. It returns the transport type plus 4 or 6
func (router_address *RouterAddress) Network() string {
	log.Debug("Getting network for RouterAddress")
	if router_address.TransportType == nil {
		log.Warn("TransportType is nil in RouterAddress")
		return ""
	}
	str, err := router_address.TransportType.Data()
	if err != nil {
		log.WithError(err).Error("Failed to get TransportType data")
		return ""
	}
	network := string(str) + router_address.IPVersion()
	log.WithField("network", network).Debug("Retrieved network for RouterAddress")
	return network
}

// IPVersion returns a string "4" for IPv4 or 6 for IPv6
func (router_address *RouterAddress) IPVersion() string {
	log.Debug("Getting IP version for RouterAddress")
	str, err := router_address.CapsString().Data()
	if err != nil {
		log.WithError(err).Error("Failed to get CapsString data")
		return ""
	}
	if strings.HasSuffix(str, IPV6_SUFFIX) {
		log.Debug("IP version is IPv6")
		return IPV6_VERSION_STRING
	}
	log.Debug("IP version is IPv4")
	return IPV4_VERSION_STRING
}

// UDP checks if the RouterAddress is UDP-based
func (router_address *RouterAddress) UDP() bool {
	log.Debug("Checking if RouterAddress is UDP")
	isUDP := strings.HasPrefix(strings.ToLower(router_address.Network()), SSU_TRANSPORT_PREFIX)
	log.WithField("is_udp", isUDP).Debug("Checked if RouterAddress is UDP")
	return isUDP
}

// String implements net.Addr. It returns the IP address, followed by the options
func (router_address *RouterAddress) String() string {
	log.Debug("Converting RouterAddress to string")
	var rv []string
	rv = append(rv, string(router_address.TransportStyle()))
	rv = append(rv, string(router_address.HostString()))
	rv = append(rv, string(router_address.PortString()))
	rv = append(rv, string(router_address.StaticKeyString()))
	rv = append(rv, string(router_address.InitializationVectorString()))
	rv = append(rv, string(router_address.ProtocolVersionString()))
	if router_address.UDP() {
		rv = append(rv, string(router_address.IntroducerHashString(0)))
		rv = append(rv, string(router_address.IntroducerExpirationString(0)))
		rv = append(rv, string(router_address.IntroducerTagString(0)))
		rv = append(rv, string(router_address.IntroducerHashString(1)))
		rv = append(rv, string(router_address.IntroducerExpirationString(1)))
		rv = append(rv, string(router_address.IntroducerTagString(1)))
		rv = append(rv, string(router_address.IntroducerHashString(2)))
		rv = append(rv, string(router_address.IntroducerExpirationString(2)))
		rv = append(rv, string(router_address.IntroducerTagString(2)))
	}
	str := strings.TrimSpace(strings.Join(rv, " "))
	log.WithField("router_address_string", str).Debug("Converted RouterAddress to string")
	return str
}

// Bytes returns the router address as a []byte.
func (router_address RouterAddress) Bytes() []byte {
	log.Debug("Converting RouterAddress to bytes")
	bytes := make([]byte, 0)
	bytes = append(bytes, router_address.TransportCost.Bytes()...)
	bytes = append(bytes, router_address.ExpirationDate.Bytes()...)
	bytes = append(bytes, router_address.TransportType...)
	bytes = append(bytes, router_address.TransportOptions.Data()...)
	log.WithField("bytes_length", len(bytes)).Debug("Converted RouterAddress to bytes")
	return bytes
}

// Cost returns the cost for this RouterAddress as a Go integer.
func (router_address RouterAddress) Cost() int {
	return router_address.TransportCost.Int()
}

// Expiration returns the expiration for this RouterAddress as an I2P Date.
func (router_address RouterAddress) Expiration() data.Date {
	return *router_address.ExpirationDate
}

// TransportStyle returns the transport style for this RouterAddress as an I2PString.
func (router_address RouterAddress) TransportStyle() data.I2PString {
	return router_address.TransportType
}

// GetOption returns the value of the option specified by the key
func (router_address RouterAddress) GetOption(key data.I2PString) data.I2PString {
	return router_address.Options().Values().Get(key)
}

// HasOption checks if a given option key exists
func (router_address RouterAddress) HasOption(key data.I2PString) bool {
	opt := router_address.GetOption(key)
	return opt != nil
}

// CheckOption checks if an option exists using a string key
func (router_address RouterAddress) CheckOption(key string) bool {
	keyv, _ := data.ToI2PString(key)
	return router_address.HasOption(keyv)
}

// HostString returns the host option as an I2PString
func (router_address RouterAddress) HostString() data.I2PString {
	host, _ := data.ToI2PString(HOST_OPTION_KEY)
	return router_address.GetOption(host)
}

// PortString returns the port option as an I2PString
func (router_address RouterAddress) PortString() data.I2PString {
	port, _ := data.ToI2PString(PORT_OPTION_KEY)
	return router_address.GetOption(port)
}

// CapsString returns the caps option as an I2PString
func (router_address RouterAddress) CapsString() data.I2PString {
	caps, _ := data.ToI2PString(CAPS_OPTION_KEY)
	return router_address.GetOption(caps)
}

// StaticKeyString returns the static key option as an I2PString
func (router_address RouterAddress) StaticKeyString() data.I2PString {
	sk, _ := data.ToI2PString(STATIC_KEY_OPTION_KEY)
	return router_address.GetOption(sk)
}

// InitializationVectorString returns the initialization vector option as an I2PString
func (router_address RouterAddress) InitializationVectorString() data.I2PString {
	iv, _ := data.ToI2PString(INITIALIZATION_VECTOR_OPTION_KEY)
	return router_address.GetOption(iv)
}

// ProtocolVersionString returns the protocol version option as an I2PString
func (router_address RouterAddress) ProtocolVersionString() data.I2PString {
	v, _ := data.ToI2PString(PROTOCOL_VERSION_OPTION_KEY)
	return router_address.GetOption(v)
}

// IntroducerHashString returns the introducer hash option for the specified number
func (router_address RouterAddress) IntroducerHashString(num int) data.I2PString {
	if num >= MIN_INTRODUCER_NUMBER && num <= MAX_INTRODUCER_NUMBER {
		val := strconv.Itoa(num)
		v, _ := data.ToI2PString(INTRODUCER_HASH_PREFIX + val)
		return router_address.GetOption(v)
	}
	v, _ := data.ToI2PString(INTRODUCER_HASH_PREFIX + strconv.Itoa(DEFAULT_INTRODUCER_NUMBER))
	return router_address.GetOption(v)
}

// IntroducerExpirationString returns the introducer expiration option for the specified number
func (router_address RouterAddress) IntroducerExpirationString(num int) data.I2PString {
	if num >= MIN_INTRODUCER_NUMBER && num <= MAX_INTRODUCER_NUMBER {
		val := strconv.Itoa(num)
		v, _ := data.ToI2PString(INTRODUCER_EXPIRATION_PREFIX + val)
		return router_address.GetOption(v)
	}
	v, _ := data.ToI2PString(INTRODUCER_EXPIRATION_PREFIX + strconv.Itoa(DEFAULT_INTRODUCER_NUMBER))
	return router_address.GetOption(v)
}

// IntroducerTagString returns the introducer tag option for the specified number
func (router_address RouterAddress) IntroducerTagString(num int) data.I2PString {
	if num >= MIN_INTRODUCER_NUMBER && num <= MAX_INTRODUCER_NUMBER {
		val := strconv.Itoa(num)
		v, _ := data.ToI2PString(INTRODUCER_TAG_PREFIX + val)
		return router_address.GetOption(v)
	}
	v, _ := data.ToI2PString(INTRODUCER_TAG_PREFIX + strconv.Itoa(DEFAULT_INTRODUCER_NUMBER))
	return router_address.GetOption(v)
}

// Host returns the host address as a net.Addr
func (router_address RouterAddress) Host() (net.Addr, error) {
	log.Debug("Getting host from RouterAddress")

	// Check if host key exists
	if !router_address.CheckOption(HOST_OPTION_KEY) {
		log.Warn("RouterAddress missing required host key")
		return nil, oops.Errorf("RouterAddress missing required '%s' key in options mapping", HOST_OPTION_KEY)
	}

	host := router_address.HostString()
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
func (router_address RouterAddress) Port() (string, error) {
	log.Debug("Getting port from RouterAddress")

	// Check if port key exists
	if !router_address.CheckOption(PORT_OPTION_KEY) {
		log.Warn("RouterAddress missing required port key")
		return "", oops.Errorf("RouterAddress missing required '%s' key in options mapping", PORT_OPTION_KEY)
	}

	port := router_address.PortString()
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
func (router_address RouterAddress) HasValidHost() bool {
	if !router_address.CheckOption(HOST_OPTION_KEY) {
		return false
	}

	host := router_address.HostString()
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
func (router_address RouterAddress) HasValidPort() bool {
	if !router_address.CheckOption(PORT_OPTION_KEY) {
		return false
	}

	port := router_address.PortString()
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

// StaticKey returns the static key as a 32-byte array
func (routerAddress RouterAddress) StaticKey() ([32]byte, error) {
	sk := routerAddress.StaticKeyString()
	if sk == nil {
		return [32]byte{}, oops.Errorf("error: static key not found")
	}

	skBytes := []byte(sk)
	if len(skBytes) != STATIC_KEY_SIZE {
		return [32]byte{}, oops.Errorf("error: invalid static key length: %d, expected %d", len(skBytes), STATIC_KEY_SIZE)
	}

	var result [32]byte
	copy(result[:], skBytes)
	return result, nil
}

// InitializationVector returns the initialization vector as a 16-byte array
func (router_address RouterAddress) InitializationVector() ([16]byte, error) {
	iv := router_address.InitializationVectorString()
	if len([]byte(iv)) != INITIALIZATION_VECTOR_SIZE {
		return [16]byte{}, oops.Errorf("error: invalid IV")
	}
	return [16]byte(iv), nil
}

// ProtocolVersion returns the protocol version as a string
func (router_address RouterAddress) ProtocolVersion() (string, error) {
	return router_address.ProtocolVersionString().Data()
}

// Options returns the options for this RouterAddress as an I2P Mapping.
func (routerAddress RouterAddress) Options() data.Mapping {
	if routerAddress.TransportOptions == nil {
		log.Warn("TransportOptions is nil in RouterAddress")
		return data.Mapping{}
	}
	return *routerAddress.TransportOptions
}

// checkValid checks if the RouterAddress is empty or if it is too small to contain valid data.
func (routerAddress RouterAddress) checkValid() (err error, exit bool) {
	if routerAddress.TransportType == nil {
		return oops.Errorf("invalid router address: nil transport type"), true
	}
	if routerAddress.TransportOptions == nil {
		return oops.Errorf("invalid router address: nil transport options"), true
	}
	return nil, false
}
