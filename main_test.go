package main

import (
	"os"
	"strconv"
	"testing"

	dns "github.com/cert-manager/cert-manager/test/acme"
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

	fixture.RunConformance(t)
}
