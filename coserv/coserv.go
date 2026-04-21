// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package coserv

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/veraison/apiclient/auth"
	"github.com/veraison/apiclient/common"
	"github.com/veraison/corim/coserv"
	"github.com/veraison/go-cose"
	"github.com/yosida95/uritemplate/v3"
)

// Media types used by CoSERV
const (
	UnsignedCoSERVMediaType = "application/coserv+cbor"
	SignedCoSERVMediaType   = "application/coserv+cose"
)

// QueryConfig holds the configuration for executing CoSERV queries.
type QueryConfig struct {
	CACerts    []string            // CA certificate paths
	Client     *common.Client      // custom HTTP client
	Auth       auth.IAuthenticator // request authentication
	UseTLS     bool                // whether to use TLS
	IsInsecure bool                // skip TLS verification

	RequestResponseURI *uritemplate.Template // URL template ending with "{query}"
}

// SetClient sets the HTTP client.
func (cfg *QueryConfig) SetClient(client *common.Client) error {
	if client == nil {
		return errors.New("no client supplied")
	}
	if cfg.Auth != nil {
		client.Auth = cfg.Auth
	}
	cfg.Client = client
	return nil
}

// SetRequestResponseURI sets the URL template (must end with "{query}").
func (cfg *QueryConfig) SetRequestResponseURI(uri string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("malformed URI: %w", err)
	}
	if !u.IsAbs() {
		return errors.New("URI is not absolute")
	}
	if !strings.HasSuffix(uri, "{query}") {
		return errors.New("URI template must end with '{query}'")
	}

	tpl, err := uritemplate.New(uri)
	if err != nil {
		return fmt.Errorf("invalid URL template: %w", err)
	}
	if len(tpl.Varnames()) != 1 {
		return errors.New("more than one variable present in endpoint")
	}

	cfg.UseTLS = u.Scheme == "https"
	cfg.RequestResponseURI = tpl
	return nil
}

// SetAuth sets the authenticator.
func (cfg *QueryConfig) SetAuth(a auth.IAuthenticator) {
	cfg.Auth = a
	if cfg.Client != nil {
		cfg.Client.Auth = cfg.Auth
	}
}

// SetIsInsecure disables TLS certificate validation (similar to DiscoveryClientBuilder).
func (cfg *QueryConfig) SetIsInsecure(val bool) {
	cfg.IsInsecure = val
}

// SetCerts sets CA certificate paths.
func (cfg *QueryConfig) SetCerts(paths []string) error {
	if len(paths) == 0 {
		return errors.New("no CA certificate paths supplied")
	}
	cfg.CACerts = paths
	return nil
}

// RunQueryForUnsignedResponse executes a query and expects an unsigned CBOR response. It returns
// a Coserv object parsed from the response.
func (cfg *QueryConfig) RunQueryForUnsignedResponse(query *coserv.Coserv) (*coserv.Coserv, error) {
	body, err := cfg.executeQuery(query, false)
	if err != nil {
		return nil, err
	}
	var result coserv.Coserv
	if err := result.FromCBOR(body); err != nil {
		return nil, fmt.Errorf("decoding unsigned CoSERV response: %w", err)
	}
	return &result, nil
}

// RunQueryForSignedResponse executes a query and returns the raw bytes.
func (cfg *QueryConfig) RunQueryForSignedResponse(query *coserv.Coserv) ([]byte, error) {
	return cfg.executeQuery(query, true)
}

// RunQueryForExtractedSignedResponse executes a query, verifies the signature, and returns the inner Coserv.
func (cfg *QueryConfig) RunQueryForExtractedSignedResponse(query *coserv.Coserv, verifier []cose.Verifier) (*coserv.Coserv, error) {
	msg, err := cfg.RunQueryForSignedResponse(query)
	if err != nil {
		return nil, err
	}
	return ExtractCoservFromSignedResponse(msg, verifier)
}

// executeQuery performs the HTTP GET with the appropriate Accept header.
func (cfg *QueryConfig) executeQuery(query *coserv.Coserv, signed bool) ([]byte, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	if err := cfg.initClient(); err != nil {
		return nil, err
	}

	b64, err := query.ToBase64Url()
	if err != nil {
		return nil, fmt.Errorf("encoding query: %w", err)
	}

	urlStr, err := cfg.RequestResponseURI.Expand(uritemplate.Values{
		"query": uritemplate.String(b64),
	})
	if err != nil {
		return nil, fmt.Errorf("expanding URL template: %w", err)
	}

	accept := UnsignedCoSERVMediaType
	if signed {
		accept = SignedCoSERVMediaType
	}

	resp, err := cfg.Client.GetResource(accept, urlStr)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if err := common.CheckResponse(resp, http.StatusOK); err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// check validates the configuration.
func (cfg *QueryConfig) check() error {
	if cfg.RequestResponseURI == nil {
		return errors.New("bad configuration: no request-response URL template")
	}
	return nil
}

// initClient creates a default client if none supplied.
func (cfg *QueryConfig) initClient() error {
	if cfg.Client != nil {
		return nil
	}
	if !cfg.UseTLS {
		cfg.Client = common.NewClient(cfg.Auth)
		return nil
	}
	if cfg.IsInsecure {
		cfg.Client = common.NewInsecureTLSClient(cfg.Auth)
		return nil
	}
	var err error
	cfg.Client, err = common.NewTLSClient(cfg.Auth, cfg.CACerts)
	return err
}

// ExtractCoservFromSignedResponse verifies the raw signed Coserv data using the provided Cose Verifiers.
// It returns a Coserv object parsed from the raw data. It returns error if none of the verifiers
// can be used to verify the signature.
func ExtractCoservFromSignedResponse(data []byte, verifiers []cose.Verifier) (*coserv.Coserv, error) {
	if len(verifiers) == 0 {
		return nil, errors.New("at least one cose verifier must be passed")
	}

	// Try verification with each provided verifier
	var result coserv.Coserv
	var verified bool
	var err error
	for _, v := range verifiers {
		if err = result.Verify(v, data); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("signature verification failed with all keys: %w", err)
	}
	return &result, nil
}
