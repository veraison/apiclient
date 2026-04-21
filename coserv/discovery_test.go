// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package coserv

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/apiclient/common"
	"github.com/veraison/corim/coserv"
)

var testBaseURI = "http://veraison.example"

func TestDiscoveryConfig_SetDiscoveryURI_Valid(t *testing.T) {
	cfg := &DiscoveryConfig{}
	err := cfg.SetDiscoveryURI("https://example.com")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com", cfg.discoveryURI)
	assert.True(t, cfg.useTLS)

	err = cfg.SetDiscoveryURI("http://insecure.com/")
	require.NoError(t, err)
	assert.Equal(t, "http://insecure.com/", cfg.discoveryURI)
	assert.False(t, cfg.useTLS)
}

func TestDiscoveryConfig_SetDiscoveryURI_Invalid(t *testing.T) {
	cfg := &DiscoveryConfig{}
	err := cfg.SetDiscoveryURI("://invalid")
	assert.Error(t, err)
	assert.ErrorContains(t, err, "malformed discovery URI")
	assert.Empty(t, cfg.discoveryURI)

	err = cfg.SetDiscoveryURI("relative/path")
	assert.Error(t, err)
	assert.EqualError(t, err, "the supplied discovery URI is not absolute")
	assert.Empty(t, cfg.discoveryURI)
}

func TestDiscoveryConfig_SetIsInsecure(t *testing.T) {
	cfg := &DiscoveryConfig{}
	assert.False(t, cfg.isInsecure)
	cfg.SetIsInsecure(true)
	assert.True(t, cfg.isInsecure)
}

func TestDiscoveryConfig_SetCerts_Valid(t *testing.T) {
	cfg := &DiscoveryConfig{}
	err := cfg.SetCerts([]string{"/path/to/ca1.pem", "/path/to/ca2.pem"})
	require.NoError(t, err)
	assert.Equal(t, []string{"/path/to/ca1.pem", "/path/to/ca2.pem"}, cfg.caCerts)
}

func TestDiscoveryConfig_SetCerts_Empty(t *testing.T) {
	cfg := &DiscoveryConfig{}
	err := cfg.SetCerts([]string{})
	assert.EqualError(t, err, "no CA certificate paths supplied")
	assert.Nil(t, cfg.caCerts)
}

func TestDiscoveryConfig_SetClient_Valid(t *testing.T) {
	cfg := &DiscoveryConfig{}
	customClient := common.NewClient(nil)
	err := cfg.SetClient(customClient)
	require.NoError(t, err)
	assert.Equal(t, customClient, cfg.client)
}

func TestDiscoveryConfig_SetClient_Nil(t *testing.T) {
	cfg := &DiscoveryConfig{}
	err := cfg.SetClient(nil)
	assert.EqualError(t, err, "no client supplied")
	assert.Nil(t, cfg.client)
}

func TestDiscoveryConfig_Run_Success(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, DiscoveryMediaTypeJson, r.Header.Get("Accept"))

		doc := coserv.DiscoveryDocument{}
		doc.SetVersion("1.2.3")

		doc.AddCapability("application/coserv+cbor", []coserv.ArtifactSupport{coserv.ArtifactSupportCollected})
		doc.AddEndPoint("CoSERVRequestResponse", "/endpoint/{query}")
		w.Header().Set("Content-Type", DiscoveryMediaTypeJson)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(doc)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := &DiscoveryConfig{}
	err := cfg.SetDiscoveryURI(testBaseURI)
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	result, err := cfg.Run()
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "1.2.3", result.Version)
	assert.Contains(t, result.ApiEndPointsMap, "CoSERVRequestResponse")
	assert.Equal(t, testBaseURI+"/endpoint/{query}", result.QueryEndpointURL)
}

func TestDiscoveryConfig_Run_NoDiscoveryURI(t *testing.T) {
	cfg := &DiscoveryConfig{}
	_, err := cfg.Run()
	assert.EqualError(t, err, "bad configuration: no discovery URI")
}

func TestDiscoveryConfig_Run_HTTPError(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := &DiscoveryConfig{}
	err := cfg.SetDiscoveryURI(testBaseURI)
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	_, err = cfg.Run()
	assert.Error(t, err)
	assert.ErrorContains(t, err, "unexpected HTTP response code")
}

func TestDiscoveryConfig_Run_InvalidJSON(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", DiscoveryMediaTypeJson)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json}`))
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := &DiscoveryConfig{}
	err := cfg.SetDiscoveryURI(testBaseURI)
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	_, err = cfg.Run()
	assert.Error(t, err)
	assert.ErrorContains(t, err, "decoding JSON discovery document")
}

func TestDiscoveryConfig_Run_InvalidCBOR(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", DiscoveryMediaTypeCbor)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid cbor}`))
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := &DiscoveryConfig{}
	err := cfg.SetDiscoveryURI(testBaseURI)
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	_, err = cfg.Run()
	assert.Error(t, err)
	assert.ErrorContains(t, err, "decoding CBOR discovery document")
}

func TestDiscoveryConfig_Run_MissingQueryEndpoint(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := coserv.DiscoveryDocument{}
		doc.SetVersion("1.2.3")
		doc.AddCapability("application/coserv+cbor", []coserv.ArtifactSupport{coserv.ArtifactSupportCollected})
		// intentionally omit CoSERVRequestResponse
		w.Header().Set("Content-Type", DiscoveryMediaTypeJson)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(doc)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := &DiscoveryConfig{}
	err := cfg.SetDiscoveryURI(testBaseURI)
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	_, err = cfg.Run()
	assert.Error(t, err)
	assert.ErrorContains(t, err, "decoding JSON discovery document: api-endpoints should not be empty")
}

func TestDiscoveryConfig_Run_InvalidEndpointPath(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := coserv.DiscoveryDocument{}
		doc.SetVersion("1.2.3")
		doc.AddCapability("application/coserv+cbor", []coserv.ArtifactSupport{coserv.ArtifactSupportCollected})
		// invalid URL path with control character
		doc.AddEndPoint("CoSERVRequestResponse", "/endpoint/\x00{query}")
		w.Header().Set("Content-Type", DiscoveryMediaTypeJson)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(doc)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := &DiscoveryConfig{}
	err := cfg.SetDiscoveryURI(testBaseURI)
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	_, err = cfg.Run()
	assert.Error(t, err)
	assert.ErrorContains(t, err, "does not end with {query}")
}

func TestDiscoveryConfig_initClient_NonTLS(t *testing.T) {
	cfg := &DiscoveryConfig{
		discoveryURI: "http://example.com",
		useTLS:       false,
	}
	err := cfg.initClient()
	require.NoError(t, err)
	assert.NotNil(t, cfg.client)
}

func TestDiscoveryConfig_initClient_TLSInsecure(t *testing.T) {
	cfg := &DiscoveryConfig{
		discoveryURI: "https://example.com",
		useTLS:       true,
		isInsecure:   true,
	}
	err := cfg.initClient()
	require.NoError(t, err)
	assert.NotNil(t, cfg.client)
}

func TestDiscoveryConfig_initClient_AlreadySet(t *testing.T) {
	customClient := common.NewClient(nil)
	cfg := &DiscoveryConfig{
		client: customClient,
	}
	err := cfg.initClient()
	require.NoError(t, err)
	assert.Equal(t, customClient, cfg.client)
}

func TestDiscoveryResult_Embedding(t *testing.T) {
	doc := &coserv.DiscoveryDocument{}
	doc.SetVersion("1.0.0")
	doc.AddCapability("application/foo", []coserv.ArtifactSupport{coserv.ArtifactSupportCollected})
	doc.AddEndPoint("CoSERVRequestResponse", "/query/{query}")

	result := &DiscoveryResult{
		DiscoveryDocument: doc,
		QueryEndpointURL:  "https://example.com/query/{query}",
	}

	assert.Equal(t, "1.0.0", result.Version)
	var called bool
	for mt, rt := range result.Capabilities() {
		assert.Equal(t, "application/foo", mt)
		assert.Equal(t, []coserv.ArtifactSupport{coserv.ArtifactSupportCollected}, rt)
		called = true
	}
	assert.True(t, called)
	assert.Equal(t, "https://example.com/query/{query}", result.QueryEndpointURL)
}

func TestDiscoveryConfig_Run_RelativePathWithAndWithoutSlashes(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := coserv.DiscoveryDocument{}
		doc.SetVersion("1.0")
		doc.AddCapability("application/coserv+cbor", []coserv.ArtifactSupport{coserv.ArtifactSupportCollected})
		doc.AddEndPoint("CoSERVRequestResponse", "endpoint/{query}") // no leading slash
		w.Header().Set("Content-Type", DiscoveryMediaTypeJson)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(doc)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := &DiscoveryConfig{}
	err := cfg.SetDiscoveryURI(testBaseURI + "/") // base with trailing slash
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	result, err := cfg.Run()
	require.NoError(t, err)
	assert.Equal(t, testBaseURI+"/endpoint/{query}", result.QueryEndpointURL)
}

func TestDiscoveryConfig_Run_NilClient_UsesDefault(t *testing.T) {
	cfg := &DiscoveryConfig{}
	err := cfg.SetDiscoveryURI(testBaseURI)
	require.NoError(t, err)
	// client is nil initially
	assert.Nil(t, cfg.client)

	result, err := cfg.Run()
	require.Error(t, err)
	assert.NotNil(t, cfg.client) // should have been initialized
	assert.Nil(t, result)
}
