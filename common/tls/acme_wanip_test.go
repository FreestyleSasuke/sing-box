package tls

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestParseWANIPJSON(t *testing.T) {
	ip, err := parseWANIP([]byte(`{"ip":"203.0.113.10","country_code":"US"}`), "4")
	if err != nil {
		t.Fatal(err)
	}
	if ip != "203.0.113.10" {
		t.Fatalf("got %s", ip)
	}
}

func TestParseWANIPPlain(t *testing.T) {
	ip, err := parseWANIP([]byte("2001:db8::1\n"), "6")
	if err != nil {
		t.Fatal(err)
	}
	if ip != "2001:db8::1" {
		t.Fatalf("got %s", ip)
	}
}

func TestParseWANIPRejectsWrongFamily(t *testing.T) {
	_, err := parseWANIP([]byte("203.0.113.10"), "6")
	if err == nil {
		t.Fatal("expected family mismatch")
	}
}

func TestFillMissingWANIPFamiliesKeepsStoredIPv6(t *testing.T) {
	got := FillMissingWANIPFamilies(
		[]string{"192.0.2.10"},
		[]string{"192.0.2.10", "2001:db8::10"},
		option.ACMEIPCheckVersionBoth,
	)
	if !SameACMESubjectSet(got, []string{"192.0.2.10", "2001:db8::10"}) {
		t.Fatalf("got %v", got)
	}
}

func TestOmittedCheckIPIntervalStaysZero(t *testing.T) {
	_, interval, err := NormalizeACMECheckIPOptions(true, "https://api.ip.sb/geoip", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if interval != 0 {
		t.Fatalf("omitted interval should stay 0, got %s", interval)
	}
	_, _, err = NormalizeACMECheckIPOptions(true, "https://api.ip.sb/geoip", badoption.Duration(time.Second), nil)
	if err == nil {
		t.Fatal("expected interval shorter than 1m to fail")
	}
}

func TestIPCheckVersionFamilies(t *testing.T) {
	if got := option.ACMEIPCheckVersion("").Families(); len(got) != 1 || got[0] != "4" {
		t.Fatalf("empty version should default to IPv4, got %v", got)
	}
	if got := option.ACMEIPCheckVersionBoth.Families(); len(got) != 2 {
		t.Fatalf("both should return two families, got %v", got)
	}
}

func TestStorageKeyHasStaleIP(t *testing.T) {
	stale := map[string]struct{}{"203.0.113.10": {}}
	key := "certificates/acme-v02.api.letsencrypt.org-directory/203.0.113.10/203.0.113.10.crt"
	if !storageKeyHasStaleIP(key, stale) {
		t.Fatal("expected stale match")
	}
	if storageKeyHasStaleIP(key, map[string]struct{}{"198.51.100.1": {}}) {
		t.Fatal("did not expect match")
	}
}

func TestMergeAndStaleSubjects(t *testing.T) {
	merged := MergeACMESubjects([]string{"example.com"}, []string{"203.0.113.10", "203.0.113.10"})
	if len(merged) != 2 {
		t.Fatalf("merge = %v", merged)
	}
	stale := staleSubjects([]string{"203.0.113.10", "example.com"}, []string{"198.51.100.1", "example.com"})
	if len(stale) != 1 || stale[0] != "203.0.113.10" {
		t.Fatalf("stale = %v", stale)
	}
}

func TestNormalizeCertificateName(t *testing.T) {
	if got := NormalizeCertificateName("[2001:db8::1]"); got != "2001:db8::1" {
		t.Fatalf("brackets: %s", got)
	}
	if got := NormalizeCertificateName("::ffff:192.0.2.10"); got != "192.0.2.10" {
		t.Fatalf("v4mapped: %s", got)
	}
	if !isUnspecifiedCertificateName("::") || !isUnspecifiedCertificateName("[::]") {
		t.Fatal(":: should be unspecified")
	}
}

type staticAddr struct {
	network string
	value   string
}

func (a staticAddr) Network() string { return a.network }
func (a staticAddr) String() string  { return a.value }

type staticConn struct {
	net.Conn
	local  net.Addr
	remote net.Addr
}

func (c staticConn) LocalAddr() net.Addr  { return c.local }
func (c staticConn) RemoteAddr() net.Addr { return c.remote }

func TestManagedNameForHelloUsesRemoteFamily(t *testing.T) {
	managed := []string{"203.0.113.10", "2001:db8::1"}
	hello := &tls.ClientHelloInfo{
		ServerName: "::",
		Conn: staticConn{
			local:  staticAddr{network: "udp", value: "[::]:443"},
			remote: staticAddr{network: "udp", value: "[2001:db8::2]:10000"},
		},
	}
	got := ManagedNameForHello(hello, managed)
	if got != "2001:db8::1" {
		t.Fatalf("expected IPv6 subject, got %q", got)
	}

	hello.Conn = staticConn{
		local:  staticAddr{network: "udp", value: "0.0.0.0:443"},
		remote: staticAddr{network: "udp", value: "198.51.100.1:10000"},
	}
	got = ManagedNameForHello(hello, managed)
	if got != "203.0.113.10" {
		t.Fatalf("expected IPv4 subject, got %q", got)
	}
}
