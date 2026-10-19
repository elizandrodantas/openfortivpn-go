//go:build darwin

package ipv4

import (
	"slices"
	"testing"
)

// Captured from scutil on macOS 15.
const scutilGlobalIPv4 = `<dictionary> {
  PrimaryInterface : en0
  PrimaryService : 3C2A1F0E-5B4D-4E6F-8A7B-9C0D1E2F3A4B
  Router : 192.168.0.1
}
`

const scutilDNS = `<dictionary> {
  SearchDomains : <array> {
    0 : example.corp
  }
  ServerAddresses : <array> {
    0 : 10.10.0.53
    1 : 10.10.0.54
  }
}
`

func TestScutilParsing(t *testing.T) {
	if got := dictValue(scutilGlobalIPv4, "PrimaryService"); got != "3C2A1F0E-5B4D-4E6F-8A7B-9C0D1E2F3A4B" {
		t.Fatalf("PrimaryService = %q", got)
	}
	if got := dictValue("  No such key\n", "PrimaryService"); got != "" {
		t.Fatalf("missing key = %q, want empty", got)
	}
	if got := arrayValues(scutilDNS, "ServerAddresses"); !slices.Equal(got, []string{"10.10.0.53", "10.10.0.54"}) {
		t.Fatalf("ServerAddresses = %v", got)
	}
	if got := arrayValues(scutilDNS, "SearchDomains"); !slices.Equal(got, []string{"example.corp"}) {
		t.Fatalf("SearchDomains = %v", got)
	}
	if got := arrayValues("  No such key\n", "ServerAddresses"); got != nil {
		t.Fatalf("missing array = %v, want nil", got)
	}
}
