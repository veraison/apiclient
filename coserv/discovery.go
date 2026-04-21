// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package coserv // or keep in package coserv if preferred

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/veraison/apiclient/common"
	"github.com/veraison/corim/coserv"
)

const (
	DiscoveryMediaTypeJson  = "application/coserv-discovery+json"
	DiscoveryMediaTypeCbor  = "application/coserv-discovery+cbor"
	WellKnownCoservEndpoint = "/.well-known/coserv-configuration"
)

// DiscoveryResult holds the fetched discovery document together with the
// absolute URL of the "CoSERVRequestResponse" endpoint.
type DiscoveryResult struct {
	*coserv.DiscoveryDocument
	QueryEndpointURL string // absolute URL, includes the "{query}" placeholder
}

// DiscoveryConfig holds configuration for fetching the CoSERV discovery document.
type DiscoveryConfig struct {
	caCerts      []string       // paths to CA certs added to system pool
	discoveryURI string         // base URL of the CoSERV server (e.g., https://veraison.example)
	client       *common.Client // optional preconfigured HTTP client
	useTLS       bool           // whether the scheme is https (set automatically from URI)
	isInsecure   bool           // skip TLS verification (only when useTLS == true)
}

// SetDiscoveryURI sets the base server URL. It must be absolute.
func (cfg *DiscoveryConfig) SetDiscoveryURI(uri string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("malformed discovery URI: %w", err)
	}
	if !u.IsAbs() {
		return errors.New("the supplied discovery URI is not absolute")
	}
	cfg.useTLS = u.Scheme == "https"
	cfg.discoveryURI = uri
	return nil
}

// SetIsInsecure enables insecure TLS connections (skip verification).
func (cfg *DiscoveryConfig) SetIsInsecure(val bool) {
	cfg.isInsecure = val
}

// SetCerts sets additional CA certificate file paths.
func (cfg *DiscoveryConfig) SetCerts(paths []string) error {
	if len(paths) == 0 {
		return errors.New("no CA certificate paths supplied")
	}
	cfg.caCerts = paths
	return nil
}

// SetClient uses a pre‑configured common.Client.
func (cfg *DiscoveryConfig) SetClient(client *common.Client) error {
	if client == nil {
		return errors.New("no client supplied")
	}
	cfg.client = client
	return nil
}

// Run fetches the discovery document from /.well-known/coserv-configuration,
// validates it, and returns a DiscoveryResult that includes the document and
// the absolute URL of the "CoSERVRequestResponse" endpoint.
func (cfg *DiscoveryConfig) Run() (*DiscoveryResult, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	if err := cfg.initClient(); err != nil {
		return nil, err
	}

	resp, err := cfg.doRequest()
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close() // ignore close error
	}()

	if cerr := common.CheckResponse(resp, http.StatusOK); cerr != nil {
		return nil, cerr
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var doc coserv.DiscoveryDocument
	if strings.Contains(resp.Header.Get("Content-Type"), DiscoveryMediaTypeCbor) {
		if cerr := doc.FromCBOR(body); cerr != nil {
			return nil, fmt.Errorf("decoding CBOR discovery document: %w", cerr)
		}
	} else if strings.Contains(resp.Header.Get("Content-Type"), DiscoveryMediaTypeJson) {
		if jerr := doc.FromJSON(body); jerr != nil {
			return nil, fmt.Errorf("decoding JSON discovery document: %w", jerr)
		}
	} else {
		return nil, fmt.Errorf("unsupported content type: %s", resp.Header.Get("Content-Type"))
	}

	queryURL, err := cfg.buildQueryEndpointURL(&doc)
	if err != nil {
		return nil, err
	}

	return &DiscoveryResult{
		DiscoveryDocument: &doc,
		QueryEndpointURL:  queryURL,
	}, nil
}

// buildQueryEndpointURL extracts the relative path from the discovery document
// and resolves it against the base URI to produce an absolute URL.
func (cfg *DiscoveryConfig) buildQueryEndpointURL(doc *coserv.DiscoveryDocument) (string, error) {
	relPath, ok := doc.ApiEndPointsMap["CoSERVRequestResponse"]
	if !ok {
		return "", errors.New("discovery document does not contain 'CoSERVRequestResponse' endpoint")
	}
	_, err := url.Parse(relPath)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint path: %w", err)
	}
	if !strings.HasSuffix(relPath, "{query}") {
		return "", errors.New("'CoSERVRequestResponse' must end with '{query}'")
	}
	// we trim the {query} path parameter before calling ResolveReference,
	// because it converts the `{` and `}` characters into some url encoded characters.
	// After resolving the base URI, we add the `{query}` suffix back to the final URL.
	rel := strings.TrimSuffix(relPath, "/{query}")
	abc, err := common.ResolveReference(cfg.discoveryURI, rel)
	if err != nil {
		return "", fmt.Errorf("resolving endpoint URL: %w", err)
	}
	return abc + "/{query}", nil
}

// check validates that required configuration is present.
func (cfg *DiscoveryConfig) check() error {
	if cfg.discoveryURI == "" {
		return errors.New("bad configuration: no discovery URI")
	}
	return nil
}

// initClient creates a default common.Client if none was provided.
func (cfg *DiscoveryConfig) initClient() error {
	if cfg.client != nil {
		return nil
	}
	if !cfg.useTLS {
		cfg.client = common.NewClient(nil) // no authenticator, no TLS
		return nil
	}
	if cfg.isInsecure {
		cfg.client = common.NewInsecureTLSClient(nil)
		return nil
	}
	var err error
	cfg.client, err = common.NewTLSClient(nil, cfg.caCerts)
	return err
}

// doRequest constructs the HTTP GET request to the well‑known discovery endpoint.
func (cfg *DiscoveryConfig) doRequest() (*http.Response, error) {
	base, err := url.Parse(cfg.discoveryURI)
	if err != nil {
		return nil, fmt.Errorf("malformed discovery URI: %w", err)
	}
	rel, err := url.Parse(WellKnownCoservEndpoint)
	if err != nil {
		return nil, fmt.Errorf("malformed well-known endpoint: %w", err)
	}
	discoveryURL := base.ResolveReference(rel).String()

	req, err := http.NewRequest("GET", discoveryURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("building discovery request: %w", err)
	}
	req.Header.Set("Accept", DiscoveryMediaTypeJson)
	req.Header.Add("Accept", DiscoveryMediaTypeCbor)
	return cfg.client.HTTPClient.Do(req)
}
