// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"
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
	UserCallback  ChallengeResponseCallback // Evidence generation logics supplied by the user
	NewSessionURI string                    // URI of the "/newSession" endpoint
	Client        *Client                   // HTTP(s) client connection configuration
	DeleteSession bool                      // explicitly DELETE the session object after we are done
}

// Blob wraps a base64 encoded value together with its media type
// (used for evidence in rats-challenge-response-session+json)
type Blob struct {
	Type  string `json:"type"`
	Value []byte `json:"value"`
}

// RatsChallengeResponseSession models the rats-challenge-response-session+json
// media type, i.e., the representation of the session resource server-side
type RatsChallengeResponseSession struct {
	Nonce    []byte          `json:"nonce"`
	Expiry   string          `json:"expiry"`
	Accept   []string        `json:"accept"`
	State    string          `json:"state"`
	Evidence Blob            `json:"evidence"`
	Result   json.RawMessage `json:"result"`
}

// Run implements the challenge-response protocol FSM invoking the user
// callback. On success, the received Attestation Result is returned.
func (cfg ChallengeResponseConfig) Run() ([]byte, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}

	// Attach the default client if the user hasn't supplied one
	if cfg.Client == nil {
		cfg.Client = NewClient()
	}

	newSessionCtx, sessionURI, err := cfg.newSession()
	if err != nil {
		return nil, fmt.Errorf("new challenge-response session creation failed: %w", err)
	}

	evidence, mediaType, err := cfg.UserCallback(newSessionCtx.Nonce, newSessionCtx.Accept)
	if err != nil {
		return nil, fmt.Errorf("evidence generation failed: %w", err)
	}

	attestationResult, err := cfg.challengeResponse(evidence, mediaType, sessionURI)

	// if requested, explicitly call DELETE on the session resource
	if cfg.DeleteSession {
		if err = cfg.deleteSession(sessionURI); err != nil {
			log.Printf("DELETE %s failed: %v", sessionURI, err)
		}
	}

	return attestationResult, err
}

func (cfg ChallengeResponseConfig) deleteSession(uri string) error {
	client := &cfg.Client.HTTPClient

	deleteSessionReq, err := http.NewRequest("DELETE", uri, nil)
	if err != nil {
		return fmt.Errorf("building request for deleting session: %w", err)
	}

	res, err := client.Do(deleteSessionReq)
	if err != nil {
		return fmt.Errorf("request for deleting session failed: %w", err)
	}

	// Expect 204
	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("deleting session response has unexpected status: %s", res.Status)
	}

	return nil
}

// newSession runs the first part of the interaction which deals with session
// creation, nonce and token format negotiation. On success, the session object
// is returned together with the URI of the new session endpoint
func (cfg ChallengeResponseConfig) newSession() (*RatsChallengeResponseSession, string, error) {
	client := &cfg.Client.HTTPClient

	newSessionReq, err := cfg.buildNewSessionRequest()
	if err != nil {
		return nil, "", fmt.Errorf("newSession request failed: %w", err)
	}

	res, err := client.Do(newSessionReq)
	if err != nil {
		return nil, "", fmt.Errorf("newSession request failed: %w", err)
	}

	// Expect 201 and a Location header containing the URI of the newly
	// allocated session
	if res.StatusCode != http.StatusCreated {
		return nil, "", fmt.Errorf("newSession response has unexpected status: %s", res.Status)
	}

	sessionURI := res.Header.Get("Location")
	if sessionURI == "" {
		return nil, "", fmt.Errorf("malformed newSession response: missing Location header")
	}

	// location may be a relative URL.  Make sure we resolve it to an absolute one
	// that can be safely used in the next API round
	sessionURI, err = cfg.resolveReference(sessionURI)
	if err != nil {
		return nil, "", fmt.Errorf(
			"newSession response: the returned Location (%s) is not a valid URI: %w",
			sessionURI, err,
		)
	}

	// Parse JSON body into a ChallengeResponseNewSessionResponse object
	defer res.Body.Close()

	j := RatsChallengeResponseSession{}

	err = json.NewDecoder(res.Body).Decode(&j)
	if err != nil {
		return nil, "", fmt.Errorf("failure decoding newSession response body: %w", err)
	}

	return &j, sessionURI, nil
}

func (cfg ChallengeResponseConfig) resolveReference(sessionURI string) (string, error) {
	u, err := url.Parse(sessionURI)
	if err != nil {
		return "", fmt.Errorf("parsing session URI: %w", err)
	}

	if u.IsAbs() {
		return sessionURI, nil
	}

	base, err := url.Parse(cfg.NewSessionURI)
	if err != nil {
		return "", fmt.Errorf("parsing base URI: %w", err)
	}

	return base.ResolveReference(u).String(), nil
}

// buildNewSessionRequest creates the POST request to the /newSession endpoint
func (cfg ChallengeResponseConfig) buildNewSessionRequest() (*http.Request, error) {
	req, err := http.NewRequest("POST", cfg.NewSessionURI, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for new session: %w", err)
	}

	// pass nonce-related info via query parameters (either nonce=3q2+7w== or
	// nonceSize=32)
	q := req.URL.Query()
	if len(cfg.Nonce) > 0 {
		q.Set("nonce", base64.StdEncoding.EncodeToString(cfg.Nonce))
	} else if cfg.NonceSz > 0 {
		q.Set("nonceSize", fmt.Sprint(cfg.NonceSz))
	}
	req.URL.RawQuery = q.Encode()

	// add the Accept header
	req.Header.Set("Accept", "application/rats-challenge-response-session+json")

	return req, nil
}

// check makes sure that the config object is in good shape
func (cfg ChallengeResponseConfig) check() error {
	if cfg.NonceSz == 0 && len(cfg.Nonce) == 0 {
		return errors.New("bad configuration: missing nonce info")
	}

	if cfg.NonceSz > 0 && len(cfg.Nonce) > 0 {
		return errors.New("bad configuration: only one of nonce or nonce size must be specified")
	}

	if cfg.UserCallback == nil {
		return errors.New("bad configuration: missing callback")
	}

	if cfg.NewSessionURI == "" {
		return errors.New("bad configuration: no API endpoint")
	}

	// It's OK if we don't have a client at this point in time; if needed we
	// will instantiate the default one later.

	return nil
}

// challengeResponse runs the second portion of the interaction protocol that
// deals with Evidence submission and retrieval of the associated Attestation
// Result.  On success, the Attestation result in JSON format is returned.
func (cfg ChallengeResponseConfig) challengeResponse(
	evidence []byte,
	mediaType string,
	uri string,
) ([]byte, error) {
	client := &cfg.Client.HTTPClient

	// build POST request with token
	sessionReq, err := cfg.buildVerificationRequest(evidence, mediaType, uri)
	if err != nil {
		return nil, fmt.Errorf("session request failed: %w", err)
	}

	res, err := client.Do(sessionReq)
	if err != nil {
		return nil, fmt.Errorf("newSession request failed: %w", err)
	}

	// switch resp.status
	switch res.StatusCode {
	case http.StatusOK:
		defer res.Body.Close()

		j := RatsChallengeResponseSession{}

		err = json.NewDecoder(res.Body).Decode(&j)
		if err != nil {
			return nil, fmt.Errorf("failure decoding session response body: %w", err)
		}

		if j.State != "complete" {
			return nil, fmt.Errorf("unexpected session state: %s", j.State)
		}

		return j.Result, nil
	case http.StatusAccepted:
		// enter a poll loop until state is either complete or failed
		return cfg.pollForAttestationResult(uri)
	default:
		// unexpected status code
		return nil, fmt.Errorf("session response has unexpected status: %s", res.Status)
	}
}

// pollForAttestationResult fetches the
func (cfg ChallengeResponseConfig) pollForAttestationResult(uri string) ([]byte, error) {
	client := &cfg.Client.HTTPClient

	// TODO(tho) make these two configurable
	const (
		pollPeriod  = 1 * time.Second
		maxAttempts = 2
	)

	for attempt := 1; attempt < maxAttempts; attempt++ {
		res, err := client.Get(uri)
		if err != nil {
			return nil, fmt.Errorf("session resource fetch failed: %w", err)
		}

		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("session resource fetch returned an unexpected status: %s", res.Status)
		}

		defer res.Body.Close()

		j := RatsChallengeResponseSession{}

		err = json.NewDecoder(res.Body).Decode(&j)
		if err != nil {
			return nil, fmt.Errorf("failure decoding session resource: %w", err)
		}

		switch j.State {
		case "complete":
			return j.Result, nil
		case "failed":
			return nil, errors.New("session resource in failed state")
		case "processing":
			time.Sleep(pollPeriod)
		default:
			return nil, fmt.Errorf("session resource in unexpected state: %s", j.State)
		}
	}

	return nil, fmt.Errorf("polling attempts exhausted, session resource state still not complete")
}

// buildVerificationRequest creates the POST request to the instantiated
// /session endpoint
func (cfg ChallengeResponseConfig) buildVerificationRequest(
	evidence []byte,
	mediaType string,
	uri string,
) (*http.Request, error) {
	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(evidence))
	if err != nil {
		return nil, fmt.Errorf("making request for verification: %w", err)
	}

	// add Content-Type as requested
	req.Header.Set("Content-Type", mediaType)

	// add the Accept header
	req.Header.Set("Accept", "application/rats-challenge-response-session+json")

	return req, nil
}
