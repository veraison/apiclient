// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/apiclient/common"
)

var (
	testDiscoveryObject = &DiscoveryObject{
		PublicKey: []byte(`{ "alg": "ES256", "crv": "P-256", "kty": "EC", "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8", "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4" }`),
		MediaTypes: []string{
			"application/vnd.enacttrust.tpm-evidence",
			"application/vnd.parallaxsecond.key-attestation.tpm",
			"application/eat+cwt; eat_profile=\"tag:psacertified.org,2023:psa#tfm\"",
			"application/vnd.veraison.tsm-report+cbor",
			"application/vnd.veraison.configfs-tsm+json",
			"application/vnd.parallaxsecond.key-attestation.cca",
			"application/psa-attestation-token",
			"application/eat-cwt; profile=\"http://arm.com/psa/2.0.0\"",
			"application/eat+cwt; eat_profile=\"tag:psacertified.org,2019:psa#legacy\"",
			"application/pem-certificate-chain",
			"application/eat-collection; profile=\"http://arm.com/CCA-SSD/1.0.0\"",
			"application/eat+cwt; eat_profile=\"tag:github.com,2025:veraison/ratsd/cmw\"",
		},
		Version:      "0.0.2511+f1ccf18",
		ServiceState: "READY",
		ApiEndpoints: map[string]string{
			"newChallengeResponseSession": "/challenge-response/v1/newSession",
		},
	}

	testDiscoveryObjectJSON = `{
  "ear-verification-key": { "alg": "ES256", "crv": "P-256", "kty": "EC", "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8", "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4" },
  "media-types": [
    "application/vnd.enacttrust.tpm-evidence",
    "application/vnd.parallaxsecond.key-attestation.tpm",
    "application/eat+cwt; eat_profile=\"tag:psacertified.org,2023:psa#tfm\"",
    "application/vnd.veraison.tsm-report+cbor",
    "application/vnd.veraison.configfs-tsm+json",
    "application/vnd.parallaxsecond.key-attestation.cca",
    "application/psa-attestation-token",
    "application/eat-cwt; profile=\"http://arm.com/psa/2.0.0\"",
    "application/eat+cwt; eat_profile=\"tag:psacertified.org,2019:psa#legacy\"",
    "application/pem-certificate-chain",
    "application/eat-collection; profile=\"http://arm.com/CCA-SSD/1.0.0\"",
    "application/eat+cwt; eat_profile=\"tag:github.com,2025:veraison/ratsd/cmw\""
  ],
  "version": "0.0.2511+f1ccf18",
  "service-state": "READY",
  "api-endpoints": {
    "newChallengeResponseSession": "/challenge-response/v1/newSession"
  }
}`
	testDiscoveryURI      = "http://discovery.example.com/.well-known/verification"
	testDiscoveryURIHTTPS = "https://discovery.example.com/.well-known/verification"
)

func TestDiscoveryConfig_Run_ok(t *testing.T) {
	var err error

	expectedBody := testDiscoveryObject

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", discoveryMediaType)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testDiscoveryObjectJSON)) // nolint: errcheck, gosec
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	var cfg DiscoveryConfig

	err = cfg.SetDiscoveryURI(testDiscoveryURI)
	require.NoError(t, err)

	err = cfg.SetClient(client)
	require.NoError(t, err)

	actualBody, err := cfg.Run()
	assert.NoError(t, err)
	assert.Equal(t, expectedBody, actualBody)
}

func TestDiscoveryConfig_Run_fail_bad_object(t *testing.T) {
	var err error

	badObject := []byte(`[ "deadbeef" ]`)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", discoveryMediaType)
		w.WriteHeader(http.StatusOK)
		w.Write(badObject) // nolint: errcheck, gosec
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	var cfg DiscoveryConfig

	err = cfg.SetDiscoveryURI(testDiscoveryURI)
	require.NoError(t, err)

	err = cfg.SetClient(client)
	require.NoError(t, err)

	_, err = cfg.Run()
	assert.ErrorContains(t, err, "failure JSON decoding response body")
}

func TestDiscoveryConfig_Run_fail_configuration(t *testing.T) {
	var err error
	var cfg DiscoveryConfig

	_, err = cfg.Run()
	assert.ErrorContains(t, err, "bad configuration: no discovery URI")
}

func TestDiscoveryConfig_Run_fail_init_tls_with_nonexistent_certs(t *testing.T) {
	var err error
	var cfg DiscoveryConfig

	err = cfg.SetDiscoveryURI(testDiscoveryURIHTTPS)
	require.NoError(t, err)

	err = cfg.SetCerts([]string{"/path/to/nonexistent/cert.pem"})
	require.NoError(t, err)

	_, err = cfg.Run()
	assert.ErrorContains(t, err, "could not read cert")
}

func TestDiscoveryConfig_Setters_fail_misc(t *testing.T) {
	var err error
	var cfg DiscoveryConfig

	err = cfg.SetDiscoveryURI("http://[::1]:namedport")
	assert.ErrorContains(t, err, "malformed discovery URI")

	err = cfg.SetDiscoveryURI("relative/path")
	assert.ErrorContains(t, err, "the supplied discovery URI is not absolute")

	err = cfg.SetCerts(nil)
	assert.ErrorContains(t, err, "no CA certificate paths supplied")

	err = cfg.SetClient(nil)
	assert.ErrorContains(t, err, "no client supplied")
}

func TestDiscoveryConfig_Setters_ok_misc(t *testing.T) {
	var err error
	var cfg DiscoveryConfig

	err = cfg.SetDiscoveryURI(testDiscoveryURIHTTPS)
	assert.NoError(t, err)

	err = cfg.SetCerts([]string{"/path/to/cert1.pem", "/path/to/cert2.pem"})
	assert.NoError(t, err)

	err = cfg.SetClient(common.NewClient(nil))
	assert.NoError(t, err)
}
