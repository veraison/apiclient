// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package provisioning

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/fxamacker/cbor/v2"
)

const (
	conciseProblemMediaType = "application/concise-problem-details+cbor"
)

// ConciseProblem is a representation of the problem details structure defined
// in RFC 9290. The response encoding format is CBOR.
type ConciseProblem struct {
	Title  string `cbor:"-1,keyasint"`
	Detail string `cbor:"-2,keyasint,omitempty"`
}

func (cp ConciseProblem) Error() string {
	return fmt.Sprintf("`%s` : `%s`", cp.Title, cp.Detail)
}

// ActivateConfig holds the context of an endorsement activate/deactivate ELM API session
type ActivateConfig struct {
	CommonConfig
	ActivateURI string // URI of the /activate or /deactivate endpoint
}

// SetActivateURI sets the Activate URI Parameter
func (cfg *ActivateConfig) SetActivateURI(uri string) error {
	scheme, err := checkURI(uri)
	if err != nil {
		return err
	}

	cfg.UseTLS = scheme == HTTPS
	cfg.ActivateURI = uri
	return nil
}

// Run() implements the Endorsement Lifecycle Mgmt. (ELM) API for activation and deactivation.
func (cfg *ActivateConfig) Run(elmQuery []byte, mediaType string) error {

	if err := cfg.check(); err != nil {
		return err
	}

	// Attach the default client if the user hasn't supplied one
	if err := cfg.initClient(); err != nil {
		return err
	}

	// POST ELM query to the endpoint
	res, err := cfg.Client.PostResource(
		elmQuery,
		mediaType,
		conciseProblemMediaType,
		cfg.ActivateURI,
	)
	if err != nil {
		return fmt.Errorf("ELM request failed: %w", err)
	}

	defer res.Body.Close() // nolint: errcheck

	// ELM query was successful
	if res.StatusCode == http.StatusNoContent {
		return nil
	}

	// Extract concise error from response body
	cp, err := conciseErrorFromResponse(res)
	if err != nil {
		return fmt.Errorf("ELM request failed with HTTP status %d, and error body could not be parsed: %w", res.StatusCode, err)
	}

	return cp
}

func (cfg ActivateConfig) check() error {
	if cfg.ActivateURI == "" {
		return errors.New("bad configuration: no ELM API endpoint")
	}

	return nil
}

func conciseErrorFromResponse(res *http.Response) (*ConciseProblem, error) {

	if res.ContentLength == 0 {
		return nil, errors.New("the response body is empty")
	}

	ct := res.Header.Get("Content-Type")
	if ct != conciseProblemMediaType {
		return nil, fmt.Errorf(
			"the response body contains unexpected content-type: %q", ct,
		)
	}

	c := ConciseProblem{}

	if err := cbor.NewDecoder(res.Body).Decode(&c); err != nil {
		return nil, fmt.Errorf("failure decoding concise error: %w", err)
	}
	return &c, nil
}
