package main

import (
	"os"
	"strconv"
	"testing"

	"github.com/cert-manager/cert-manager/test/acme/dns"
)

// I use commit hashes in the links below just to ensure the line numbers are
// correct.

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

	// Options available:  https://github.com/cert-manager/cert-manager/blob/3a055cc2f56c1c2874807af4a8f84d0a1c46ccb4/test/acme/dns/options.go#L100-L177
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
	// Only use RunConfirmance() alone, once the PR is merged. Or if it is not
	// merged, use both RunBasic() and RunExtended(), but not RunConfirmance().

	//fixture.RunConformance(t)

	// The tests work, except they hang on the wait.PollUntil functions here:
	// https://github.com/cert-manager/cert-manager/blob/b1180c59ad588e73ac25b0d70a86661cf7c180e1/test/acme/dns/suite.go#L46
	// https://github.com/cert-manager/cert-manager/blob/b1180c59ad588e73ac25b0d70a86661cf7c180e1/test/acme/dns/suite.go#L59
	// I haven't diagnosed why, but I validated that the present and cleanup
	// functions complete *and return* successfully and yet the tests still
	// hang. (I've also just straight used the webhook in practice and made
	// sure it works as expected.)
	fixture.RunBasic(t)
	fixture.RunExtended(t)
}
