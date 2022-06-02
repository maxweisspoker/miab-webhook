package main

import (
	"os"
	"strconv"
	"testing"

	"github.com/cert-manager/cert-manager/test/acme/dns"
)

func TestRunsSuite(t *testing.T) {
	zone := os.Getenv("TEST_ZONE_NAME")
	if zone == "" {
		zone = "example.com." // Zone is your base TLD with a period at the end
	}

	useAuthoritative := os.Getenv("TEST_USE_AUTHORITATIVE")
	if useAuthoritative == "" {
		useAuthoritative = "false"
	}
	useAuthoritativeBool, _ := strconv.ParseBool(useAuthoritative)

	// The manifest path in dns.SetManifestPath should contain a file named
	// config.json that is a snippet of valid configuration that should be
	// included on theChallengeRequest passed as part of the test cases.

	// Options available:  https://github.com/cert-manager/cert-manager/blob/master/test/acme/dns/options.go#L100-L177
	fixture := dns.NewFixture(&miabSolver{},
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath("testdata/miab-webhook"),
		dns.SetDNSName("cert-manager-dns01-tests.example.com"),
		dns.SetStrict(true),
		dns.SetDNSServer("0.0.0.0:53"), // Use MIAB server IP here with port 53
		dns.SetUseAuthoritative(useAuthoritativeBool),
	)

	// Once https://github.com/cert-manager/cert-manager/pull/4835 is merged,
	// you should uncomment and use fixture.RunConformance(t), and comment out
	// or delete RunBasic() and RunExtended(). Do not use all of them together.
	// Only use RunConfirmance() alone, once the PR is merged, or if it is not
	// merged, use both RunBasic() and RunExtended() but not RunConfirmance().

	//fixture.RunConformance(t)

	fixture.RunBasic(t)
	fixture.RunExtended(t)
}
