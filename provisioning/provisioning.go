// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package provisioning

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/veraison/apiclient/auth"
	"github.com/veraison/apiclient/common"
)

const (
	sessionMediaType = "application/vnd.veraison.provisioning-session+json"
)

// SubmitSession models the application/vnd.veraison.provisioning-session+json
// media type
type SubmitSession struct {
	Status        string  `json:"status"`
	Expiry        string  `json:"expiry"`
	FailureReason *string `json:"failure-reason"`
}

// SubmitConfig holds the context of an endorsement submission API session
type SubmitConfig struct {
	CACerts       []string            // paths to CA certs to be used in addition to system certs for TLS connections
	Client        *common.Client      // HTTP(s) client connection configuration
	SubmitURI     string              // URI of the /submit endpoint
	Auth          auth.IAuthenticator // when set, Auth supplies the Authorization header for requests
	DeleteSession bool                // explicitly DELETE the session object after we are done
	UseTLS        bool                // use TLS for server connections
	IsInsecure    bool                // allow insecure server connections (only matters when UseTLS is true)
}

// SetClient sets the HTTP(s) client connection configuration
func (cfg *SubmitConfig) SetClient(client *common.Client) error {
	if client == nil {
		return errors.New("no client supplied")
	}

	if cfg.Auth != nil {
		client.Auth = cfg.Auth
	}

	cfg.Client = client
	return nil
}

// SetSubmitURI sets the URI Parameter
func (cfg *SubmitConfig) SetSubmitURI(uri string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("malformed URI: %w", err)
	}
	if !u.IsAbs() {
		return errors.New("uri is not absolute")
	}
	cfg.UseTLS = u.Scheme == "https"
	cfg.SubmitURI = uri
	return nil
}

// SetDeleteSession instruct to DELETE the session object after it is complete
func (cfg *SubmitConfig) SetDeleteSession(session bool) {
	cfg.DeleteSession = session
}

// SetAuth sets the IAuthenticator that will be used
func (cfg *SubmitConfig) SetAuth(a auth.IAuthenticator) {
	cfg.Auth = a
	if cfg.Client != nil {
		cfg.Client.Auth = cfg.Auth
	}
}

// SetIsInsecure sets the IsInsecure parameter using the supplied val
func (cfg *SubmitConfig) SetIsInsecure(val bool) {
	cfg.IsInsecure = val
}

// SetCerts sets the CACerts parameter to the specified paths
func (cfg *SubmitConfig) SetCerts(paths []string) {
	cfg.CACerts = paths
}

// Run implements the endorsement submission API.  If the session does not
// complete synchronously, this call will block until either the session state
// moves out of the processing state, or the MaxAttempts*PollPeriod threshold is
// hit. On success, returns the final SubmitSession with status information.
func (cfg SubmitConfig) Run(endorsement []byte, mediaType string) (*SubmitSession, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}

	// Attach the default client if the user hasn't supplied one
	if err := cfg.initClient(); err != nil {
		return nil, err
	}

	// POST endorsement to the /submit endpoint
	res, err := cfg.Client.PostResource(
		endorsement,
		mediaType,
		sessionMediaType,
		cfg.SubmitURI,
	)
	if err != nil {
		return nil, fmt.Errorf("submit request failed: %w", err)
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected HTTP response code %d", res.StatusCode)
	}

	// if 200 or 201, we have been returned the provisioning session resource in
	// the response body
	j, err := sessionFromResponse(res)
	if err != nil {
		return nil, err
	}

	// see whether the server is handling our request synchronously or not
	// (sync)
	if res.StatusCode == http.StatusOK {
		if j.Status == common.APIStatusSuccess {
			return j, nil
		} else if j.Status == common.APIStatusFailed {
			s := "submission failed"
			if j.FailureReason != nil {
				s += fmt.Sprintf(": %s", *j.FailureReason)
			}
			return nil, errors.New(s)
		}
		return nil, fmt.Errorf("unexpected session state %q in 200 response", j.Status)
	}

	// (async)
	// expect 'processing' status
	if j.Status != common.APIStatusProcessing {
		return nil, fmt.Errorf("unexpected session state %q in 201 response", j.Status)
	}

	sessionURI, err := common.ExtractLocation(res, cfg.SubmitURI)
	if err != nil {
		return nil, fmt.Errorf("cannot determine URI for the session resource: %w", err)
	}

	session, err := cfg.pollForSubmissionCompletion(sessionURI)

	// if requested, explicitly call DELETE on the session resource
	if cfg.DeleteSession {
		if delErr := cfg.Client.DeleteResource(sessionURI); delErr != nil {
			log.Printf("DELETE %s failed: %v", sessionURI, delErr)
		}
	}

	return session, err
}

// pollForSubmissionCompletion polls the supplied URI while the resource state
// is "processing".  If the resource state is still "processing" when the
// configured number of polls has been attempted, or the state of the resource
// transitions to "failed", or an unexpected HTTP status is encountered, an
// error is returned. On success, returns the final SubmitSession.
func (cfg SubmitConfig) pollForSubmissionCompletion(uri string) (*SubmitSession, error) {
	client := &cfg.Client.HTTPClient

	for attempt := 1; attempt < common.MaxAttempts; attempt++ {
		res, err := client.Get(uri)
		if err != nil {
			return nil, fmt.Errorf("session resource fetch failed: %w", err)
		}

		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("session resource fetch returned an unexpected status: %s", res.Status)
		}

		j, err := sessionFromResponse(res)
		if err != nil {
			return nil, err
		}

		switch j.Status {
		case common.APIStatusSuccess:
			return j, nil
		case common.APIStatusFailed:
			s := "submission failed"
			if j.FailureReason != nil {
				s += fmt.Sprintf(": %s", *j.FailureReason)
			}
			return nil, errors.New(s)
		case common.APIStatusProcessing:
			time.Sleep(common.PollPeriod)
		default:
			return nil, fmt.Errorf("unexpected session state %q in 200 response", j.Status)
		}
	}

	return nil, fmt.Errorf("polling attempts exhausted, session resource state still not complete")
}

func (cfg SubmitConfig) check() error {
	if cfg.SubmitURI == "" {
		return errors.New("bad configuration: no API endpoint")
	}

	return nil
}

func sessionFromResponse(res *http.Response) (*SubmitSession, error) {
	if res.ContentLength == 0 {
		return nil, errors.New("empty body")
	}

	ct := res.Header.Get("Content-Type")
	if ct != sessionMediaType {
		return nil, fmt.Errorf(
			"session resource with unexpected content type: %q", ct,
		)
	}

	j := SubmitSession{}

	if err := common.DecodeJSONBody(res, &j); err != nil {
		return nil, fmt.Errorf("failure decoding session resource: %w", err)
	}

	return &j, nil
}

func (cfg *SubmitConfig) initClient() error {
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
