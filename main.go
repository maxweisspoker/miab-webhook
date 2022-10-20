package main

import (
	// Embed tzdata and Mozilla TLS certs for completely static FROM scratch build
	_ "time/tzdata"

	_ "github.com/breml/rootcerts"

	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	k8s "k8s.io/client-go/kubernetes"
	k8srest "k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"

	miab "github.com/maxweisspoker/miabhttp"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// Auto-set in the Helm chart to be the chart namespace, but if you've put
	// it somewhere else and configured the RBAC permissions to access it, you
	// can manually set this to something else
	if os.Getenv("CREDS_SECRET_NAMESPACE") == "" {
		panic("CREDS_SECRET_NAMESPACE must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&miabSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type miabSolver struct {
	miabcontext *miab.Context
	k8sclient   *k8s.Clientset
	uidtracker  map[apimachinerytypes.UID]time.Time // Keep track of when last action for UID was performed, to prevent DOSing miab server
	uiddiffsec  int32                               // How long to wait before retrying the action for the same UID. If ΔT<uiddiffsec, then present/cleanup just return successfully without actually doing anything.
	shouldstop  bool                                // Bg thread sets this when it detects <-stopCh
	mutex       sync.Mutex                          // Both bg thread and present/cleanup may mutate this struct, we we use old-school mutex.
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.

// This is the data fields entered in the Issuer config section.
// For example:
//
// apiVersion: cert-manager.io/v1
// kind: Issuer
// metadata:
//
//	name: example-issuer
//
// spec:
//
//	acme:
//	 ...
//	  solvers:
//	  - dns01:
//	      webhook:
//	        groupName: $UNIQUE_GROUP_NAME_EG_YOUR_BOX_DOMAIN
//	        solverName: mail-in-a-box
//	        config:
//	          MiabContextSecretName: "miab-context-secret" # This is the name of the Secret resource. See testdata folder for example.
type miabSolverConfig struct {
	// Key/value data for secret are listed in miabhttp.CreateMiabContext() params
	// See testdata folder for example.
	MiabContextSecretName string `json:"miabContextSecretName"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *miabSolver) Name() string {
	return "mail-in-a-box"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
//
// TLDR:  Add TXT record for domain ch.ResolvedFQDN
func (c *miabSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	// Lock mutex because we might modify the miabSolver, and don't want to
	// clash with the backgroundRunner or CleanUp().
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.shouldstop {
		return errors.New("not performing Present() because <-stopCh has signalled and we are in the process of terminating")
	}

	if strings.ToLower(string(ch.Action)) != "present" && string(ch.Action) != "" {
		return errors.New("present method called with invalid ChallengeRequest.Action: " + string(ch.Action))
	}

	if strings.ToLower(string(ch.Type)) != "dns-01" && strings.ToLower(string(ch.Type)) != "dns01" && string(ch.Type) != "" {
		return errors.New("unknown ChallengeRequest.Type: " + string(ch.Type))
	}

	if string(ch.UID) != "" {
		if t, ok := c.uidtracker[ch.UID]; ok {
			if td, e := time.ParseDuration(strconv.Itoa(int(c.uiddiffsec)) + "s"); e == nil && time.Since(t) <= td {
				return nil
			}
		}
	}

	// Create miab context if necessary. Can't do this in Init(), so we must do it here
	if err := c.setMiabContext(ch); err != nil {
		return err
	}

	// If the record already exists, do nothing
	existingRecords, err := c.miabcontext.GetDnsCustomRecordsForQNameAndType(strings.TrimRight(ch.ResolvedFQDN, "."), "TXT")
	if err != nil {
		return err
	}
	existingRecordsSlice := existingRecords.([]map[string]interface{})
	for _, record := range existingRecordsSlice {
		if record["qname"].(string) == strings.TrimRight(ch.ResolvedFQDN, ".") {
			if record["value"].(string) == ch.Key {
				if string(ch.UID) != "" {
					c.uidtracker[ch.UID] = time.Now()
				}
				return nil
			}
		}
	}

	// Most MIAB instances are small machines, so we give it a moment between requests
	time.Sleep(100 * time.Millisecond)

	// If we've gotten here without returning, the record doesn't exist, so we
	// add it
	_, err = c.miabcontext.AddDnsCustomRecord(strings.TrimRight(ch.ResolvedFQDN, "."), "TXT", ch.Key)
	if err != nil {
		return err
	}

	// Give the server another break and then perform an update
	time.Sleep(100 * time.Millisecond)
	c.miabcontext.UpdateDns(0)

	if string(ch.UID) != "" {
		c.uidtracker[ch.UID] = time.Now()
	}
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
//
// TLDR: Delete TXT record for domain ch.ResolvedFQDN
func (c *miabSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	// Lock mutex because we might modify the miabSolver, and don't want to
	// clash with the backgroundRunner or Present().
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.shouldstop {
		return errors.New("not performing CleanUp() because <-stopCh has signalled and we are in the process of terminating")
	}

	// Create miab context if necessary. Can't do this in Init(), so we must do it here
	if strings.ToLower(string(ch.Action)) != "cleanup" && strings.ToLower(string(ch.Action)) != "clean-up" && string(ch.Action) != "" {
		return errors.New("cleanup method called with invalid ChallengeRequest.Action: " + string(ch.Action))
	}

	if strings.ToLower(string(ch.Type)) != "dns-01" && strings.ToLower(string(ch.Type)) != "dns01" && string(ch.Type) != "" {
		return errors.New("unknown ChallengeRequest.Type: " + string(ch.Type))
	}

	if string(ch.UID) != "" {
		if t, ok := c.uidtracker[ch.UID]; ok {
			if td, e := time.ParseDuration(strconv.Itoa(int(c.uiddiffsec)) + "s"); e == nil && time.Since(t) <= td {
				return nil
			}
		}
	}

	// Create miab context if necessary. Can't do this in Init(), so we must do it here
	if err := c.setMiabContext(ch); err != nil {
		return err
	}

	// If the record doesn't exist, we don't need to do anything
	existingRecords, err := c.miabcontext.GetDnsCustomRecordsForQNameAndType(strings.TrimRight(ch.ResolvedFQDN, "."), "TXT")
	if err != nil {
		return err
	}
	found := false
	existingRecordsSlice := existingRecords.([]map[string]interface{})
	for _, record := range existingRecordsSlice {
		if record["qname"].(string) == strings.TrimRight(ch.ResolvedFQDN, ".") {
			if record["value"].(string) == ch.Key {
				found = true
				break
			}
		}
	}
	if !found {
		if string(ch.UID) != "" {
			c.uidtracker[ch.UID] = time.Now()
		}
		return nil
	}

	// Most MIAB instances are small machines, so we give it a moment between requests
	time.Sleep(100 * time.Millisecond)

	// Delete the TXT record
	_, err = c.miabcontext.RemoveDnsCustomRecord(strings.TrimRight(ch.ResolvedFQDN, "."), "TXT", ch.Key)
	if err != nil {
		return err
	}

	// Give the server another break and then do an update
	time.Sleep(100 * time.Millisecond)
	c.miabcontext.UpdateDns(0)

	if string(ch.UID) != "" {
		c.uidtracker[ch.UID] = time.Now()
	}
	return nil
}

// Sets time limits for repeated checks based on env vars, and launches
// backgroundRunner
func (c *miabSolver) Initialize(kubeClientConfig *k8srest.Config, stopCh <-chan struct{}) error {
	cl, err := k8s.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.k8sclient = cl
	c.shouldstop = false
	c.miabcontext = nil

	uidtimecheck := os.Getenv("UID_DIFF_CHECK_SEC")
	if uidtimecheck == "" {
		c.uiddiffsec = 5 // MIAB handles multiple requests pretty well, so this doesn't need to be too high
	} else {
		uidtime, err := strconv.Atoi(uidtimecheck)
		if err != nil || uidtime < 1 {
			return errors.New("env var UID_DIFF_CHECK_SEC is not a positive integer")
		}
		c.uiddiffsec = int32(uidtime)
	}

	var bgperiod int32 = 0
	bgsleepperiod := os.Getenv("BGRUNNER_SEC_PERIOD")
	if bgsleepperiod == "" {
		bgperiod = 1 // This doesn't do too much normally, so there's no harm running it over and over, and I want it to catch stopCh within a few seconds, so having a short period is probably best
	} else {
		bgp, err := strconv.Atoi(bgsleepperiod)
		if err != nil || bgp < 1 {
			return errors.New("env var BGRUNNER_SEC_PERIOD is not a positive integer")
		}
		bgperiod = int32(bgp)
	}

	var uidtimetodelete int32 = 0
	uidtimediff := os.Getenv("UID_DIFF_DELETE_SEC")
	if uidtimediff == "" {
		uidtimetodelete = 300
	} else {
		uidtime, err := strconv.Atoi(uidtimediff)
		if err != nil || uidtime < 1 {
			return errors.New("env var UID_DIFF_DELETE_SEC is not a positive integer")
		}
		uidtimetodelete = int32(uidtime)
	}

	// Bg thread
	go c.backgroundRunner(bgperiod, uidtimetodelete, stopCh)

	return nil
}

// Config from Issuer is loaded into the ChallengeRequest, so Present and
// CleanUp can extract it and parse it into the miabSolverConfig struct here.
func loadConfig(cfgJSON *extapi.JSON) (miabSolverConfig, error) {
	cfg := miabSolverConfig{}

	if cfgJSON == nil {
		return cfg, nil
	}

	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

// Background thread. Watches for stopCh and garbage collects miabSolver.uidtracker map
func (c *miabSolver) backgroundRunner(sleepTime, uidDiffDelete int32, stopCh <-chan struct{}) {
	for {
		time.Sleep(time.Duration(sleepTime) * time.Second)

		c.mutex.Lock()

		select {
		case <-stopCh:
			c.shouldstop = true
			if c.miabcontext != nil {
				// c.miabcontext.Logout() // Not necessary since we are always using user/pass currently
				c.miabcontext = nil
			}
			c.mutex.Unlock()
			return
		default:
		}

		keysToDelete := []apimachinerytypes.UID{}
		for uid, timeOfLastOp := range c.uidtracker {
			timediff := int32(time.Since(timeOfLastOp).Seconds())
			if timediff > uidDiffDelete {
				keysToDelete = append(keysToDelete, uid)
			}
		}
		for _, uid := range keysToDelete {
			delete(c.uidtracker, uid)
		}

		c.mutex.Unlock()
	}
}

// Should only be called when mutex is locked, since it changes solver struct state
func (c *miabSolver) setMiabContext(ch *v1alpha1.ChallengeRequest) error {
	if c.miabcontext == nil {

		cfg, err := loadConfig(ch.Config)
		if err != nil {
			return err
		}

		secret, err := c.k8sclient.CoreV1().Secrets(os.Getenv("CREDS_SECRET_NAMESPACE")).Get(context.TODO(), cfg.MiabContextSecretName, metav1.GetOptions{})
		if err != nil {
			return errors.New("error importing the miab credentials secret: " + err.Error())
		}

		c.miabcontext, err = miab.CreateMiabContext(
			string(secret.Data["server"]), "",
			string(secret.Data["username"]),
			string(secret.Data["password"]),
			"", "") // TODO: Add the ability to set API key or OTP code and add recycling the API key to the backgroundRunner
		if err != nil {
			// c.miabcontext = nil    // CreateMiabContext() returns nil for Context on error, so no need to nil it manually
			return errors.New("miabhttp.CreateMiabContext() error: " + err.Error())
		}
	}
	return nil
}
