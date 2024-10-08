// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/veraison/apiclient/auth"
	"github.com/veraison/apiclient/common"
	"github.com/veraison/cmw"
)

type CmwWrap int

const (
	NoWrap CmwWrap = iota
	WrapCBOR
	WrapJSON
)

type cmwInfo struct {
	mt string
	s  cmw.Serialization
}

var cmwInfoMap = map[CmwWrap]cmwInfo{
	WrapCBOR: {mt: "application/vnd.veraison.cmw+cbor", s: cmw.CBORArray},
	WrapJSON: {mt: "application/vnd.veraison.cmw+json", s: cmw.JSONArray},
}

// ChallengeResponseConfig holds the configuration for one or more
// challenge-response exchanges
type ChallengeResponseConfig struct {
	Nonce           []byte              // an explicit nonce supplied by the user
	CACerts         []string            // paths to CA certs to be used in addition to system certs for TLS connections
	NonceSz         uint                // the size of a nonce to be provided by server
	EvidenceBuilder EvidenceBuilder     // Evidence generation logics supplied by the user
	NewSessionURI   string              // URI of the "/newSession" endpoint
	Client          *common.Client      // HTTP(s) client connection configuration
	Wrap            CmwWrap             // when set, wrap the supplied evidence as a Conceptual Message Wrapper(CMW)
	Auth            auth.IAuthenticator // when set, Auth supplies the Authorization header for requests
	DeleteSession   bool                // explicitly DELETE the session object after we are done
	UseTLS          bool                // use TLS for server connections
	IsInsecure      bool                // allow insecure server connections (only matters when UseTLS is true)
}

// Blob wraps a base64 encoded value together with its media type
// (used for evidence in rats-challenge-response-session+json)
type Blob struct {
	Type  string `json:"type"`
	Value []byte `json:"value"`
}

// ChallengeResponseSession models the rats-challenge-response-session+json
// media type, i.e., the representation of the session resource server-side
type ChallengeResponseSession struct {
	Nonce    []byte          `json:"nonce"`
	Expiry   string          `json:"expiry"`
	Accept   []string        `json:"accept"`
	Status   string          `json:"status"`
	Evidence Blob            `json:"evidence"`
	Result   json.RawMessage `json:"result"`
}

// SetNonce sets the Nonce supplied by the user
func (cfg *ChallengeResponseConfig) SetNonce(nonce []byte) error {
	if len(nonce) == 0 {
		return errors.New("no nonce supplied")
	}
	cfg.Nonce = nonce
	return nil
}

// SetNonceSz sets the nonce size supplied by the user
func (cfg *ChallengeResponseConfig) SetNonceSz(nonceSz uint) error {
	if nonceSz == 0 {
		return errors.New("zero nonce size supplied")
	}
	cfg.NonceSz = nonceSz
	return nil
}

// SetEvidenceBuilder sets the Evidence Builder callback supplied by the user
func (cfg *ChallengeResponseConfig) SetEvidenceBuilder(evidenceBuilder EvidenceBuilder) error {
	if evidenceBuilder == nil {
		return errors.New("no evidence builder supplied")
	}
	cfg.EvidenceBuilder = evidenceBuilder
	return nil
}

// SetSessionURI sets the New Session URI supplied by the user
func (cfg *ChallengeResponseConfig) SetSessionURI(uri string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("malformed session URI: %w", err)
	}
	if !u.IsAbs() {
		return errors.New("the supplied session URI is not in absolute form")
	}
	cfg.UseTLS = u.Scheme == "https"
	cfg.NewSessionURI = uri
	return nil
}

// SetIsInsecure sets the IsInsecure parameter using the supplied val
func (cfg *ChallengeResponseConfig) SetIsInsecure(val bool) {
	cfg.IsInsecure = val
}

// SetCerts sets the CACerts parameter to the specified paths
func (cfg *ChallengeResponseConfig) SetCerts(paths []string) {
	cfg.CACerts = paths
}

// SetClient sets the HTTP(s) client connection configuration
func (cfg *ChallengeResponseConfig) SetClient(client *common.Client) error {
	if client == nil {
		return errors.New("no client supplied")
	}
	cfg.Client = client
	return nil
}

// SetDeleteSession sets the DeleteSession parameter using the supplied val
func (cfg *ChallengeResponseConfig) SetDeleteSession(val bool) {
	cfg.DeleteSession = val
}

func isValidCmwWrap(val CmwWrap) bool {
	switch val {
	case NoWrap, WrapCBOR, WrapJSON:
		return true
	default:
		return false
	}
}

// SetWrap sets the Wrap parameter using the supplied val
func (cfg *ChallengeResponseConfig) SetWrap(val CmwWrap) error {
	if isValidCmwWrap(val) {
		cfg.Wrap = val
		return nil
	}
	return fmt.Errorf("invalid CMW Wrap: %d", val)
}

// Run implements the challenge-response protocol FSM invoking the user
// callback. On success, the received Attestation Result is returned.
func (cfg *ChallengeResponseConfig) Run() ([]byte, error) {
	if err := cfg.check(true); err != nil {
		return nil, err
	}

	// Attach the default client if the user hasn't supplied one
	if err := cfg.initClient(); err != nil {
		return nil, err
	}

	newSessionCtx, sessionURI, err := cfg.newSession()
	if err != nil {
		return nil, fmt.Errorf("new challenge-response session creation failed: %w", err)
	}

	evidence, mediaType, err := cfg.EvidenceBuilder.BuildEvidence(newSessionCtx.Nonce, newSessionCtx.Accept)
	if err != nil {
		return nil, fmt.Errorf("evidence generation failed: %w", err)
	}

	if cfg.Wrap != NoWrap {
		evidence, mediaType, err = cfg.wrapEvInCMW(evidence, mediaType)
		if err != nil {
			return nil, err
		}
	}

	return cfg.ChallengeResponse(evidence, mediaType, sessionURI)
}

func (cfg ChallengeResponseConfig) wrapEvInCMW(evidence []byte, mt string) ([]byte, string, error) {
	c := &cmw.CMW{}
	c.SetMediaType(mt)
	c.SetValue(evidence)
	c.SetIndicators(cmw.Evidence)
	cmi, ok := cmwInfoMap[cfg.Wrap]
	if !ok {
		return nil, "", fmt.Errorf("unable to get cmw info for Wrap: %d", cfg.Wrap)
	}

	cm, err := c.Serialize(cmi.s)
	if err != nil {
		return nil, "", fmt.Errorf("cmw serialization failed: %w", err)
	}
	return cm, cmi.mt, nil
}

// NewSession runs the first part of the interaction which deals with session
// creation, nonce and token format negotiation. On success, the session object
// is returned together with the URI of the new session endpoint
func (cfg ChallengeResponseConfig) NewSession() (*ChallengeResponseSession, string, error) {
	if err := cfg.check(false); err != nil {
		return nil, "", err
	}

	// Attach the default client if the user hasn't supplied one
	if err := cfg.initClient(); err != nil {
		return nil, "", err
	}

	return cfg.newSession()
}

// ChallengeResponse runs the second portion of the interaction protocol that
// deals with Evidence submission and retrieval of the associated Attestation
// Result.  On success, the Attestation result in JSON format is returned.
func (cfg ChallengeResponseConfig) ChallengeResponse(
	evidence []byte,
	mediaType string,
	uri string,
) ([]byte, error) {
	// At this point we must assume we have a Client
	if cfg.Client == nil {
		return nil, errors.New("bad configuration: nil client")
	}

	attestationResult, err := cfg.challengeResponse(evidence, mediaType, uri)

	// if requested, explicitly call DELETE on the session resource

	if cfg.DeleteSession {
		if err2 := cfg.Client.DeleteResource(uri); err2 != nil {
			log.Printf("DELETE %s failed: %v", uri, err2)
		}
	}

	return attestationResult, err
}

func (cfg ChallengeResponseConfig) newSession() (*ChallengeResponseSession, string, error) {
	res, err := cfg.newSessionRequest()
	if err != nil {
		return nil, "", fmt.Errorf("newSession request failed: %w", err)
	}

	// Expect 201 and a Location header containing the URI of the newly
	// allocated session
	if res.StatusCode != http.StatusCreated {
		return nil, "", fmt.Errorf("newSession response has unexpected status: %s", res.Status)
	}

	sessionURI, err := common.ExtractLocation(res, cfg.NewSessionURI)
	if err != nil {
		return nil, "", fmt.Errorf("cannot determine URI for the session resource: %w", err)
	}

	j := ChallengeResponseSession{}

	// Parse JSON body into a ChallengeResponseSession object
	err = common.DecodeJSONBody(res, &j)
	if err != nil {
		return nil, "", fmt.Errorf("failure JSON decoding response body: %w", err)
	}

	return &j, sessionURI, nil
}

// newSessionRequest creates the POST request to the /newSession endpoint
func (cfg ChallengeResponseConfig) newSessionRequest() (*http.Response, error) {
	req, err := http.NewRequest("POST", cfg.NewSessionURI, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("building request for new session: %w", err)
	}

	// pass nonce-related info via query parameters (either nonce=3q2+7w== or
	// nonceSize=32)
	q := req.URL.Query()
	if len(cfg.Nonce) > 0 {
		q.Set("nonce", base64.URLEncoding.EncodeToString(cfg.Nonce))
	} else if cfg.NonceSz > 0 {
		q.Set("nonceSize", fmt.Sprint(cfg.NonceSz))
	}
	req.URL.RawQuery = q.Encode()

	// add the Accept header
	req.Header.Set("Accept", "application/vnd.veraison.challenge-response-session+json")

	hc := &cfg.Client.HTTPClient

	res, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("newSession request failed: %w", err)
	}

	return res, nil
}

// check makes sure that the config object is in good shape
func (cfg ChallengeResponseConfig) check(atomicRun bool) error {
	if cfg.NonceSz == 0 && len(cfg.Nonce) == 0 {
		return errors.New("bad configuration: missing nonce info")
	}

	if cfg.NonceSz > 0 && len(cfg.Nonce) > 0 {
		return errors.New("bad configuration: only one of nonce or nonce size must be specified")
	}

	if cfg.NewSessionURI == "" {
		return errors.New("bad configuration: no API endpoint")
	}

	if atomicRun {
		if cfg.EvidenceBuilder == nil {
			return errors.New("bad configuration: the evidence builder is missing")
		}
	} else {
		if cfg.EvidenceBuilder != nil {
			return errors.New("bad configuration: found non-nil evidence builder in non-atomic mode")
		}
	}

	// It's OK if we don't have a client at this point in time; if needed we
	// will instantiate the default one later.

	return nil
}

func (cfg ChallengeResponseConfig) challengeResponse(
	evidence []byte,
	mediaType string,
	uri string,
) ([]byte, error) {
	// build POST request with attestation evidence
	res, err := cfg.Client.PostResource(
		evidence,
		mediaType,
		"application/vnd.veraison.challenge-response-session+json",
		uri,
	)
	if err != nil {
		return nil, fmt.Errorf("session request failed: %w", err)
	}

	// switch resp.status
	switch res.StatusCode {
	case http.StatusOK:
		j := ChallengeResponseSession{}

		err = common.DecodeJSONBody(res, &j)
		if err != nil {
			return nil, fmt.Errorf("failure decoding session resource body: %w", err)
		}

		if j.Status != common.APIStatusComplete {
			return nil, fmt.Errorf("unexpected session state: %s", j.Status)
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

// pollForAttestationResult polls the supplied URI until the resource state
// transitions to "complete". If so, the attestation result is returned. If the
// resource state is still "processing" when the configured number of polls has
// been attempted, or the state of the resource transitions to "failed", an
// error is returned.
func (cfg ChallengeResponseConfig) pollForAttestationResult(uri string) ([]byte, error) {
	client := &cfg.Client.HTTPClient

	for attempt := 1; attempt < common.MaxAttempts; attempt++ {
		res, err := client.Get(uri)
		if err != nil {
			return nil, fmt.Errorf("session resource fetch failed: %w", err)
		}

		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("session resource fetch returned an unexpected status: %s", res.Status)
		}

		j := ChallengeResponseSession{}

		err = common.DecodeJSONBody(res, &j)
		if err != nil {
			return nil, fmt.Errorf("failure decoding session resource: %w", err)
		}

		switch j.Status {
		case common.APIStatusComplete:
			return j.Result, nil
		case common.APIStatusFailed:
			return nil, errors.New("session resource in failed state")
		case common.APIStatusProcessing:
			time.Sleep(common.PollPeriod)
		default:
			return nil, fmt.Errorf("session resource in unexpected state: %s", j.Status)
		}
	}

	return nil, fmt.Errorf("polling attempts exhausted, session resource state still not complete")
}

func (cfg *ChallengeResponseConfig) initClient() error {
	if cfg.Client != nil {
		return nil // client already initialized
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
