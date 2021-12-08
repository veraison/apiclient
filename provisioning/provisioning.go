// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package provisioning

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

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
	Client        *common.Client // HTTP(s) client connection configuration
	SubmitURI     string         // URI of the /submit endpoint
	DeleteSession bool           // explicitly DELETE the session object after we are done
}

// Run implements the endorsement submission API.  If the session does not
// complete synchronously, this call will block until either the session state
// moves out of the processing state, or the MaxAttempts*PollPeriod threshold is
// hit.
func (cfg SubmitConfig) Run(endorsement []byte, mediaType string) error {
	if err := cfg.check(); err != nil {
		return err
	}

	if cfg.Client == nil {
		cfg.Client = common.NewClient()
	}

	// POST endorsement to the /submit endpoint
	res, err := cfg.Client.PostResource(
		endorsement,
		mediaType,
		sessionMediaType,
		cfg.SubmitURI,
	)
	if err != nil {
		return fmt.Errorf("submit request failed: %w", err)
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected HTTP response code %d", res.StatusCode)
	}

	// if 200 or 201, we have been returned the provisioning session resource in
	// the response body
	j, err := sessionFromResponse(res)
	if err != nil {
		return err
	}

	// see whether the server is handling our request synchronously or not
	// (sync)
	if res.StatusCode == http.StatusOK {
		if j.Status == common.APIStatusSuccess {
			return nil
		} else if j.Status == common.APIStatusFailed {
			s := "submission failed"
			if j.FailureReason != nil {
				s += fmt.Sprintf(": %s", *j.FailureReason)
			}
			return errors.New(s)
		}
		return fmt.Errorf("unexpected session state %q in 200 response", j.Status)
	}

	// (async)
	// expect 'processing' status
	if j.Status != common.APIStatusProcessing {
		return fmt.Errorf("unexpected session state %q in 201 response", j.Status)
	}

	sessionURI, err := common.ExtractLocation(res, cfg.SubmitURI)
	if err != nil {
		return fmt.Errorf("cannot determine URI for the session resource: %w", err)
	}

	err = cfg.pollForSubmissionCompletion(sessionURI)

	// if requested, explicitly call DELETE on the session resource
	if cfg.DeleteSession {
		if err = cfg.Client.DeleteResource(sessionURI); err != nil {
			log.Printf("DELETE %s failed: %v", sessionURI, err)
		}
	}

	return err
}

// pollForSubmissionCompletion polls the supplied URI while the resource state
// is "processing".  If the resource state is still "processing" when the
// configured number of polls has been attempted, or the state of the resource
// transitions to "failed", or an unexpected HTTP status is encountered, an
// error is returned.
func (cfg SubmitConfig) pollForSubmissionCompletion(uri string) error {
	client := &cfg.Client.HTTPClient

	for attempt := 1; attempt < common.MaxAttempts; attempt++ {
		res, err := client.Get(uri)
		if err != nil {
			return fmt.Errorf("session resource fetch failed: %w", err)
		}

		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("session resource fetch returned an unexpected status: %s", res.Status)
		}

		j, err := sessionFromResponse(res)
		if err != nil {
			return err
		}

		switch j.Status {
		case common.APIStatusSuccess:
			return nil
		case common.APIStatusFailed:
			s := "submission failed"
			if j.FailureReason != nil {
				s += fmt.Sprintf(": %s", *j.FailureReason)
			}
			return errors.New(s)
		case common.APIStatusProcessing:
			time.Sleep(common.PollPeriod)
		default:
			return fmt.Errorf("unexpected session state %q in 200 response", j.Status)
		}
	}

	return fmt.Errorf("polling attempts exhausted, session resource state still not complete")
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
