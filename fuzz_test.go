package ip_test

import (
	"net/netip"
	"testing"

	"github.com/skarm/ip"
)

func FuzzParseForwarded(f *testing.F) {
	for _, seed := range []string{
		`for=192.0.2.1`,
		`for="[2001:db8::1]:443";proto=https`,
		`for=unknown, for=198.51.100.1`,
		`for="unterminated`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > ip.DefaultMaxHeaderBytes {
			t.Skip()
		}
		addrs, _ := ip.ParseForwarded(value)
		assertNormalizedAddrs(t, addrs)
	})
}

func FuzzParseXForwardedFor(f *testing.F) {
	for _, seed := range []string{
		"192.0.2.1",
		"198.51.100.1, 10.0.0.1",
		"unknown, 192.0.2.1",
		"bad-token, 192.0.2.1",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > ip.DefaultMaxHeaderBytes {
			t.Skip()
		}
		addrs, _ := ip.ParseXForwardedFor(value)
		assertNormalizedAddrs(t, addrs)
	})
}

func FuzzUnknownXForwardedForHopIsTrustBoundary(f *testing.F) {
	const maxAttackerBytes = 1024

	for _, seed := range []string{"198.51.100.1", "spoofed", "", "198.51.100.1, 203.0.113.5"} {
		f.Add(seed)
	}

	ex := ip.Must(ip.New(
		ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"),
		ip.WithMaxHeaderBytes(8<<10),
		ip.WithMaxHops(maxAttackerBytes+3),
		ip.WithMaxTokenBytes(2<<10),
	))

	f.Fuzz(func(t *testing.T, attackerControlled string) {
		if len(attackerControlled) > maxAttackerBytes {
			t.Skip()
		}
		value := attackerControlled + ", unknown, 10.0.0.1"
		result, err := ex.ExtractResultFrom(
			map[string][]string{ip.XForwardedFor: {value}},
			"10.0.0.2:443",
		)
		if err != nil {
			t.Fatalf("ExtractResultFrom() error = %v", err)
		}
		if result.Addr.String() != "10.0.0.2" || result.Reason != ip.ReasonUnverifiableChain {
			t.Fatalf("attacker-controlled prefix crossed trust boundary: %+v", result)
		}
	})
}

func FuzzForwardedElementWithoutForIsTrustBoundary(f *testing.F) {
	f.Add([]byte{198, 51, 100, 7})
	f.Add([]byte{192, 0, 2, 55})

	ex := ip.Must(ip.New(
		ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"),
		ip.WithMaxHeaderBytes(8<<10),
		ip.WithMaxTokenBytes(2<<10),
	))

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) < 4 {
			t.Skip()
		}
		prefix := netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]})
		value := "for=" + prefix.String() + ", by=203.0.113.9;proto=https, for=10.0.0.1"
		result, err := ex.ExtractResultFrom(
			map[string][]string{ip.Forwarded: {value}},
			"10.0.0.2:443",
		)
		if err != nil {
			t.Fatalf("ExtractResultFrom() error = %v", err)
		}
		if result.Addr.String() != "10.0.0.2" || result.Reason != ip.ReasonUnverifiableChain {
			t.Fatalf("attacker-controlled prefix crossed missing-for boundary: %+v", result)
		}
	})
}

func FuzzEmptyXForwardedForElementIsTrustBoundary(f *testing.F) {
	f.Add([]byte{198, 51, 100, 7})
	f.Add([]byte{192, 0, 2, 55})

	ex := ip.Must(ip.New(
		ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"),
		ip.WithMaxHeaderBytes(8<<10),
		ip.WithMaxTokenBytes(2<<10),
	))

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) < 4 {
			t.Skip()
		}
		prefix := netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]})
		value := prefix.String() + ", , 10.0.0.1"
		result, err := ex.ExtractResultFrom(
			map[string][]string{ip.XForwardedFor: {value}},
			"10.0.0.2:443",
		)
		if err != nil {
			t.Fatalf("ExtractResultFrom() error = %v", err)
		}
		if result.Addr.String() != "10.0.0.2" || result.Reason != ip.ReasonUnverifiableChain {
			t.Fatalf("attacker-controlled prefix crossed empty-hop boundary: %+v", result)
		}
	})
}

func assertNormalizedAddrs(t *testing.T, addrs []netip.Addr) {
	t.Helper()
	for _, addr := range addrs {
		if !addr.IsValid() {
			t.Fatalf("parser returned invalid address: %v", addr)
		}
		if addr != addr.Unmap().WithZone("") {
			t.Fatalf("parser returned non-normalized address: %v", addr)
		}
	}
}
