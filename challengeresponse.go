// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ChallengeResponseCallback is the interface between the challenge-response
// protocol FSM and the user. The user is given a nonce and the list of
// acceptable Evidence formats and is asked to return the serialized Evidence as
// a byte array together with its media type - or an error if anything goes
// wrong.
type ChallengeResponseCallback func(nonce []byte, accept []string) (evidence []byte, mediaType string, err error)

// ChallengeResponseConfig holds the configuration for one or more
// challenge-response exchanges
type ChallengeResponseConfig struct {
	Nonce         []byte                    // an explicit nonce supplied by the user
	NonceSz       uint                      // the size of a nonce to be provided by server
	Callback      ChallengeResponseCallback // Evidence generation logics supplied by the user
	NewSessionURI string                    // URI of the "/newSession" endpoint
	Client        *Client                   // HTTP(s) client connection
}

// ChallengeResponseNewSessionResponse models the body of the server response to
// a newSession request
type ChallengeResponseNewSessionResponse struct {
	Nonce  []byte   `json:"nonce"`
	Expiry string   `json:"expiry"`
	Accept []string `json:"accept"`
	State  string   `json:"state"`
}

// Run implements the challenge-response protocol FSM invoking the user
// callback. On success, the received Attestation Result and its media type are
// returned.
func (cfg ChallengeResponseConfig) Run() ([]byte, string, error) {
	if err := cfg.check(); err != nil {
		return nil, "", err
	}

	// Attach the default client if the user hasn't supplied one
	if cfg.Client == nil {
		cfg.Client = NewClient()
	}

	newSessionCtx, sessionURI, err := cfg.newSession()
	if err != nil {
		return nil, "", fmt.Errorf("new challenge-response failed: %w", err)
	}

	evidence, mediaType, err := cfg.Callback(newSessionCtx.Nonce, newSessionCtx.Accept)
	if err != nil {
		return nil, "", fmt.Errorf("evidence generation failed: %w", err)
	}

	return runChallengeResponse(evidence, mediaType, sessionURI)
}

func runChallengeResponse(evidence []byte, mediaType string, uri string) ([]byte, string, error) {
	return nil, "", errors.New("TODO")
}

// newSession runs the first part of the interaction which deals with session
// creation, nonce and token format negotiation. On success, the session object
// is returned together with the URI of the new session endpoint
func (cfg ChallengeResponseConfig) newSession() (*ChallengeResponseNewSessionResponse, string, error) {
	client := &cfg.Client.HTTPClient

	newSessionReq, err := cfg.buildNewSessionRequest()
	if err != nil {
		return nil, "", fmt.Errorf("building request for new session: %w", err)
	}

	res, err := client.Do(newSessionReq)
	if err != nil {
		return nil, "", fmt.Errorf("making request for new session: %w", err)
	}

	// Expect 201 and a Location header containing the URI of the newly
	// allocated session
	if res.StatusCode != http.StatusCreated {
		return nil, "", fmt.Errorf("new session response has unexpected status: %s", res.Status)
	}

	sessionURI := res.Header.Get("Location")
	if sessionURI == "" {
		return nil, "", fmt.Errorf("malformed new session response: missing Location header")
	}

	// Parse JSON body into a ChallengeResponseNewSessionResponse object
	defer res.Body.Close()

	j := ChallengeResponseNewSessionResponse{}

	err = json.NewDecoder(res.Body).Decode(&j)
	if err != nil {
		return nil, "", fmt.Errorf("reading new session response body: %w", err)
	}

	return &j, sessionURI, nil
}

func (cfg ChallengeResponseConfig) buildNewSessionRequest() (*http.Request, error) {
	req, err := http.NewRequest("POST", cfg.NewSessionURI, nil)
	if err != nil {
		return nil, fmt.Errorf("making request for new session: %w", err)
	}

	// pass nonce information query parameters
	q := req.URL.Query()
	if len(cfg.Nonce) > 0 {
		q.Set("nonce", base64.StdEncoding.EncodeToString(cfg.Nonce))
	} else if cfg.NonceSz > 0 {
		q.Set("nonceSz", fmt.Sprint(cfg.NonceSz))
	}
	req.URL.RawQuery = q.Encode()

	// add the accept header
	req.Header.Add("Accept", "application/rats-challenge-response-session+json")

	return req, nil
}

func (cfg ChallengeResponseConfig) check() error {
	if cfg.NonceSz == 0 && len(cfg.Nonce) == 0 {
		return errors.New("bad configuration: missing nonce info")
	}

	if cfg.Callback == nil {
		return errors.New("bad configuration: missing callback")
	}

	if cfg.NewSessionURI == "" {
		return errors.New("bad configuration: no API endpoint")
	}

	// It's OK to not have a client at this point in time; if needed we will
	// instantiate the default one later.

	return nil
}
