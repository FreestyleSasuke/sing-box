package tls

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/caddyserver/certmagic"
)

// ACMERenewalWatchInterval is how often we look at cached certificates when
// check_ip_interval is omitted. This does not query check_ip_url by itself.
const ACMERenewalWatchInterval = 30 * time.Minute

const acmeWANIPRequestTimeout = 15 * time.Second

// NormalizeACMECheckIPOptions validates check_ip settings.
// An omitted check_ip_interval stays zero: WAN IP is resolved at startup and
// again when certmagic marks a managed certificate for renewal.
func NormalizeACMECheckIPOptions(checkIP bool, url string, interval badoption.Duration, domains []string) (string, time.Duration, error) {
	if !checkIP {
		if len(domains) == 0 {
			return "", 0, E.New("missing domain")
		}
		return url, interval.Build(), nil
	}
	url = strings.TrimSpace(url)
	if url == "" {
		return "", 0, E.New("check_ip_url is required when check_ip is enabled")
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return "", 0, E.New("check_ip_url must be an absolute HTTP(S) URL")
	}
	resolved := interval.Build()
	if resolved < 0 {
		return "", 0, E.New("invalid check_ip_interval: ", interval.Build())
	}
	if resolved > 0 && resolved < time.Minute {
		return "", 0, E.New("check_ip_interval must be at least 1m when set")
	}
	return url, resolved, nil
}

// ManagedCertificatesNeedRenewal reports whether any managed name is missing
// from the cache or is inside certmagic's renewal window.
func ManagedCertificatesNeedRenewal(cache *certmagic.Cache, cfg *certmagic.Config, names []string) bool {
	if cache == nil || cfg == nil || len(names) == 0 {
		return true
	}
	for _, name := range names {
		certs := cache.AllMatchingCertificates(name)
		if len(certs) == 0 {
			return true
		}
		for _, certificate := range certs {
			if certificate.Empty() || certificate.Expired() || certificate.NeedsRenewal(cfg) {
				return true
			}
		}
	}
	return false
}

// WANIPDiscovery is the result of probing check_ip_url per address family.
type WANIPDiscovery struct {
	IPs             []string
	FailedFamilies  []string
	FamilyErrors    []error
}

// DiscoverWANIPs queries checkURL once per requested address family.
// network is forced to tcp4 or tcp6 so dual-stack hosts return the matching WAN address.
func DiscoverWANIPs(ctx context.Context, checkURL string, version option.ACMEIPCheckVersion) ([]string, error) {
	result, err := DiscoverWANIPsDetailed(ctx, checkURL, version)
	if err != nil {
		return nil, err
	}
	return result.IPs, nil
}

func DiscoverWANIPsDetailed(ctx context.Context, checkURL string, version option.ACMEIPCheckVersion) (WANIPDiscovery, error) {
	families := version.Families()
	result := WANIPDiscovery{}
	var lastErr error
	for _, family := range families {
		ip, err := lookupWANIP(ctx, checkURL, family)
		if err != nil {
			lastErr = err
			result.FailedFamilies = append(result.FailedFamilies, family)
			result.FamilyErrors = append(result.FamilyErrors, err)
			continue
		}
		result.IPs = append(result.IPs, ip)
	}
	result.IPs = uniqueStrings(result.IPs)
	if len(result.IPs) == 0 {
		if lastErr != nil {
			return result, lastErr
		}
		return result, E.New("failed to discover WAN IP from ", checkURL)
	}
	return result, nil
}

func hasIPFamily(names []string, ipv6 bool) bool {
	return FirstIPSubjectByFamily(names, ipv6) != ""
}

// FillMissingWANIPFamilies keeps stored certs for a family when the echo
// lookup for that family failed. "both" must not drop IPv6 management just
// because check_ip_url failed over tcp6.
func FillMissingWANIPFamilies(discovered, stored []string, version option.ACMEIPCheckVersion) []string {
	merged := append([]string{}, discovered...)
	for _, family := range version.Families() {
		wantV6 := family == "6"
		if hasIPFamily(merged, wantV6) {
			continue
		}
		if fallback := FirstIPSubjectByFamily(stored, wantV6); fallback != "" {
			merged = append(merged, fallback)
		}
	}
	return uniqueStrings(merged)
}

// StoredIPSubjects lists IP certificate site names already in certmagic storage.
func StoredIPSubjects(ctx context.Context, storage certmagic.Storage) []string {
	if storage == nil {
		return nil
	}
	keys, err := storage.List(ctx, "certificates/", true)
	if err != nil {
		return nil
	}
	var ips []string
	for _, key := range keys {
		for _, part := range strings.Split(key, "/") {
			part = strings.TrimSuffix(part, ".crt")
			part = strings.TrimSuffix(part, ".key")
			part = strings.TrimSuffix(part, ".json")
			part = strings.TrimSuffix(part, ".pem")
			ip := net.ParseIP(part)
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				ips = append(ips, v4.String())
				continue
			}
			ips = append(ips, ip.String())
		}
	}
	return uniqueStrings(ips)
}

func lookupWANIP(ctx context.Context, checkURL string, family string) (string, error) {
	network := "tcp4"
	if family == "6" {
		network = "tcp6"
	}
	dialer := &net.Dialer{Timeout: acmeWANIPRequestTimeout}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   acmeWANIPRequestTimeout,
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
	if err != nil {
		return "", E.Cause(err, "create WAN IP request")
	}
	req.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.1")
	req.Header.Set("User-Agent", "sing-box-acme-check-ip")

	resp, err := client.Do(req)
	if err != nil {
		return "", E.Cause(err, "query WAN IP (", network, ") from ", checkURL)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", E.Cause(err, "read WAN IP response")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", E.New("WAN IP endpoint returned HTTP ", resp.StatusCode)
	}
	ip, err := parseWANIP(body, family)
	if err != nil {
		return "", err
	}
	return ip, nil
}

func parseWANIP(body []byte, family string) (string, error) {
	text := strings.TrimSpace(string(body))
	if ip := net.ParseIP(trimQuotes(text)); ip != nil {
		return matchIPFamily(ip, family)
	}

	var generic map[string]any
	if json.Unmarshal(body, &generic) == nil {
		for _, key := range []string{"ip", "query", "origin", "address", "wan_ip", "ipAddress", "ipv4", "ipv6"} {
			raw, ok := generic[key]
			if !ok {
				continue
			}
			value, ok := raw.(string)
			if !ok {
				continue
			}
			if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil {
				if formatted, err := matchIPFamily(ip, family); err == nil {
					return formatted, nil
				}
			}
		}
	}

	for _, token := range strings.FieldsFunc(text, func(r rune) bool {
		return r == '"' || r == '\'' || r == ',' || r == ';' || r == '<' || r == '>' ||
			r == '(' || r == ')' || r == '[' || r == ']' || r == '{' || r == '}' ||
			r == '=' || r == ':' || r == '/' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) {
		if ip := net.ParseIP(token); ip != nil {
			if formatted, err := matchIPFamily(ip, family); err == nil {
				return formatted, nil
			}
		}
	}
	return "", E.New("WAN IP endpoint did not return a usable IPv", family, " address")
}

func matchIPFamily(ip net.IP, family string) (string, error) {
	if ip == nil {
		return "", E.New("empty IP")
	}
	if family == "6" {
		if ip.To4() != nil {
			return "", E.New("expected IPv6, got IPv4 ", ip)
		}
		if ip.To16() == nil {
			return "", E.New("invalid IPv6 address")
		}
		return ip.String(), nil
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return "", E.New("expected IPv4, got IPv6 ", ip)
	}
	return ipv4.String(), nil
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// MergeACMESubjects appends discovered WAN IPs to any statically configured names.
func MergeACMESubjects(staticNames []string, wanIPs []string) []string {
	return uniqueStrings(append(append([]string{}, staticNames...), wanIPs...))
}

func subjectSet(names []string) map[string]struct{} {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		set[name] = struct{}{}
	}
	return set
}

// StaleACMESubjects returns names present in previous but not in current.
func StaleACMESubjects(previous, current []string) []string {
	return staleSubjects(previous, current)
}

func staleSubjects(previous, current []string) []string {
	keep := subjectSet(current)
	var stale []string
	for _, name := range previous {
		if _, ok := keep[name]; ok {
			continue
		}
		stale = append(stale, name)
	}
	return stale
}

// FirstIPSubject returns the first IPv4 name, or the first IP if no IPv4 exists.
func FirstIPSubject(names []string) string {
	return firstIPSubject(names)
}

func firstIPSubject(names []string) string {
	var fallback string
	for _, name := range names {
		ip := net.ParseIP(name)
		if ip == nil {
			continue
		}
		if fallback == "" {
			fallback = name
		}
		if ip.To4() != nil {
			return name
		}
	}
	return fallback
}

// CleanupStaleACMECertificates removes persisted certmagic certificate assets
// whose site name is an IP address that is no longer being managed.
func CleanupStaleACMECertificates(ctx context.Context, storage certmagic.Storage, cache *certmagic.Cache, stale []string) error {
	if storage == nil || len(stale) == 0 {
		return nil
	}
	staleSet := subjectSet(stale)
	if cache != nil {
		var hashes []string
		for _, name := range stale {
			for _, certificate := range cache.AllMatchingCertificates(name) {
				if hash := certificate.Hash(); hash != "" {
					hashes = append(hashes, hash)
				}
			}
		}
		if len(hashes) > 0 {
			cache.Remove(hashes)
		}
	}
	keys, err := storage.List(ctx, "certificates/", true)
	if err != nil {
		return E.Cause(err, "list ACME certificate storage")
	}
	for _, key := range keys {
		if !storageKeyHasStaleIP(key, staleSet) {
			continue
		}
		err = storage.Delete(ctx, key)
		if err != nil {
			return E.Cause(err, "delete stale ACME certificate ", key)
		}
	}
	return nil
}

func storageKeyHasStaleIP(key string, stale map[string]struct{}) bool {
	for _, part := range strings.Split(key, "/") {
		part = strings.TrimSuffix(part, ".crt")
		part = strings.TrimSuffix(part, ".key")
		part = strings.TrimSuffix(part, ".json")
		part = strings.TrimSuffix(part, ".pem")
		ip := net.ParseIP(part)
		if ip == nil {
			continue
		}
		if _, ok := stale[ip.String()]; ok {
			return true
		}
		if v4 := ip.To4(); v4 != nil {
			if _, ok := stale[v4.String()]; ok {
				return true
			}
		}
	}
	return false
}

// SameACMESubjectSet reports whether a and b contain the same names.
func SameACMESubjectSet(a, b []string) bool {
	return sameStringSet(a, b)
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left := subjectSet(a)
	for _, value := range b {
		if _, ok := left[value]; !ok {
			return false
		}
	}
	return true
}

// NormalizeCertificateName canonicalizes SNI / IP identifiers.
// IPv6 brackets are stripped and IPv4-mapped addresses become dotted IPv4.
func NormalizeCertificateName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, "[")
	name = strings.TrimSuffix(name, "]")
	if ip := net.ParseIP(name); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return strings.ToLower(name)
}

func isUnspecifiedCertificateName(name string) bool {
	switch NormalizeCertificateName(name) {
	case "", "::", "0.0.0.0":
		return true
	default:
		return false
	}
}

func matchManagedName(managed []string, candidate string) string {
	normalized := NormalizeCertificateName(candidate)
	if normalized == "" {
		return ""
	}
	for _, name := range managed {
		if NormalizeCertificateName(name) == normalized {
			return name
		}
	}
	return ""
}

// FirstIPSubjectByFamily returns a managed IP of the requested family.
func FirstIPSubjectByFamily(names []string, ipv6 bool) string {
	for _, name := range names {
		ip := net.ParseIP(name)
		if ip == nil {
			continue
		}
		isV4 := ip.To4() != nil
		if ipv6 && !isV4 {
			return name
		}
		if !ipv6 && isV4 {
			return name
		}
	}
	return ""
}

func addrIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch typed := addr.(type) {
	case *net.TCPAddr:
		return typed.IP
	case *net.UDPAddr:
		return typed.IP
	case *net.IPAddr:
		return typed.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			host = addr.String()
		}
		return net.ParseIP(strings.Trim(host, "[]"))
	}
}

func helloConnIPs(hello *tls.ClientHelloInfo) (localIP, remoteIP net.IP) {
	if hello == nil || hello.Conn == nil {
		return nil, nil
	}
	return addrIP(hello.Conn.LocalAddr()), addrIP(hello.Conn.RemoteAddr())
}

// ManagedNameForHello picks the ACME subject that should be served for this handshake.
//
// IP clients (especially QUIC/Hysteria2) often send an empty SNI, or the listen
// address "::". certmagic then falls back to DefaultServerName, which was the
// IPv4 WAN address, so IPv6 clients received the IPv4 certificate.
func ManagedNameForHello(hello *tls.ClientHelloInfo, managed []string) string {
	if hello == nil || len(managed) == 0 {
		return ""
	}
	sni := NormalizeCertificateName(hello.ServerName)
	if !isUnspecifiedCertificateName(sni) {
		if name := matchManagedName(managed, sni); name != "" {
			return name
		}
	}
	localIP, remoteIP := helloConnIPs(hello)
	if localIP != nil && !localIP.IsUnspecified() {
		if name := matchManagedName(managed, localIP.String()); name != "" {
			return name
		}
		if name := FirstIPSubjectByFamily(managed, localIP.To4() == nil); name != "" {
			return name
		}
	}
	if remoteIP != nil {
		if name := FirstIPSubjectByFamily(managed, remoteIP.To4() == nil); name != "" {
			return name
		}
	}
	return ""
}

// HelloWithCertificateName returns a ClientHello whose ServerName is name.
func HelloWithCertificateName(hello *tls.ClientHelloInfo, name string) *tls.ClientHelloInfo {
	if hello == nil || name == "" {
		return hello
	}
	if NormalizeCertificateName(hello.ServerName) == NormalizeCertificateName(name) {
		return hello
	}
	clone := *hello
	clone.ServerName = name
	return &clone
}
