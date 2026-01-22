// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/veraison/apiclient/common"
)

var discoveryMediaType = "application/vnd.veraison.discovery+json"

// DiscoveryConfig holds the configuration for one or more retrievals from the discovery endpoint.
type DiscoveryConfig struct {
	caCerts      []string       // paths to CA certs to be used in addition to system certs for TLS connections
	discoveryURI string         // URI of the discovery endpoint
	client       *common.Client // HTTP(s) client connection configuration
	useTLS       bool           // use TLS for server connections
	isInsecure   bool           // allow insecure server connections (only matters when UseTLS is true)
}

type DiscoveryObject struct {
	PublicKey    json.RawMessage   `json:"ear-verification-key,omitempty"`
	MediaTypes   []string          `json:"media-types,omitempty"`
	Schemes      []string          `json:"attestation-schemes,omitempty"`
	Version      string            `json:"version"`
	ServiceState string            `json:"service-state"`
	ApiEndpoints map[string]string `json:"api-endpoints"`
}

// SetDiscoveryURI sets the discovery URI supplied by the user
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

// SetIsInsecure sets the flag to allow insecure server connections
func (cfg *DiscoveryConfig) SetIsInsecure() {
	cfg.isInsecure = true
}

// SetCerts sets the CA certificates to the specified paths
func (cfg *DiscoveryConfig) SetCerts(paths []string) error {
	if len(paths) == 0 {
		return errors.New("no CA certificate paths supplied")
	}
	cfg.caCerts = paths
	return nil
}

// SetClient sets the HTTP(s) client connection configuration
func (cfg *DiscoveryConfig) SetClient(client *common.Client) error {
	if client == nil {
		return errors.New("no client supplied")
	}
	cfg.client = client
	return nil
}

// Run retrieves the discovery document from the configured endpoint.
// On success, the decoded discovery document is returned.
func (cfg *DiscoveryConfig) Run() (*DiscoveryObject, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}

	// Attach the default client if the user hasn't supplied one
	if err := cfg.initClient(); err != nil {
		return nil, err
	}

	res, err := cfg.discovery()
	if err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}

	j := DiscoveryObject{}

	err = common.DecodeJSONBody(res, &j)
	if err != nil {
		return nil, fmt.Errorf("failure JSON decoding response body: %w", err)
	}

	return &j, nil
}

// discovery creates the GET request to the discovery endpoint and returns the response
func (cfg DiscoveryConfig) discovery() (*http.Response, error) {
	req, err := http.NewRequest("GET", cfg.discoveryURI, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("building discovery request: %w", err)
	}

	// add the Accept header
	req.Header.Set("Accept", discoveryMediaType)

	hc := &cfg.client.HTTPClient

	res, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}

	return res, nil
}

// check makes sure that the config object is in good shape
func (cfg DiscoveryConfig) check() error {
	if cfg.discoveryURI == "" {
		return errors.New("bad configuration: no discovery URI")
	}

	// It's OK if we don't have a client at this point in time; if needed we
	// will instantiate the default one later.

	return nil
}

func (cfg *DiscoveryConfig) initClient() error {
	if cfg.client != nil {
		return nil // client already initialized
	}

	if !cfg.useTLS {
		// Use a nil authenticator.
		// The (reasonable) assumption is that the discovery endpoint is always
		// unauthenticated.
		cfg.client = common.NewClient(nil)
		return nil
	}

	if cfg.isInsecure {
		// Ditto about the nil authenticator.
		cfg.client = common.NewInsecureTLSClient(nil)
		return nil
	}

	var err error

	cfg.client, err = common.NewTLSClient(nil, cfg.caCerts)

	return err
}
