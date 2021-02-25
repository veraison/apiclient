// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testNonce []byte = []byte{0xde, 0xad, 0xbe, 0xef}
var testEvidence []byte = []byte{0x0e, 0x0d, 0x0e}

func userCallBackOK(nonce []byte, accept []string) (evidence []byte, mediaType string, err error) {
	return testEvidence, "application/my-evidence-media-type", nil
}

// newTestingHTTPClient creates an HTTP test server (with a configurable request
// handler), an API Client and connects them together.  The API client and the
// server's shutdown switch are returned.
func newTestingHTTPClient(handler http.Handler) (cli *Client, closerFn func()) {
	srv := httptest.NewServer(handler)

	cli = &Client{
		HTTPClient: http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
					return net.Dial(network, srv.Listener.Addr().String())
				},
			},
		},
	}

	closerFn = srv.Close

	return
}

func TestChallengeResponseConfig_newSession_ok(t *testing.T) {
	newSessionCreatedBody := `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "state": "waiting"	
}`

	expectedBody := &RatsChallengeResponseSession{
		Nonce:  testNonce,
		Expiry: "2030-10-12T07:20:50.52Z",
		Accept: []string{
			"application/psa-attestation-token",
		},
		State: "waiting",
	}

	expectedSessionURI := "http://veraison.example/challenge-response/v1/session/1"

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "3q2+7w==", r.URL.Query().Get("nonce"))
		assert.Equal(t, "application/rats-challenge-response-session+json", r.Header.Get("Accept"))

		w.Header().Set("Location", expectedSessionURI)
		w.WriteHeader(http.StatusCreated)
		_, e := w.Write([]byte(newSessionCreatedBody))
		require.Nil(t, e)
	})

	client, teardown := newTestingHTTPClient(h)
	defer teardown()

	cfg := ChallengeResponseConfig{
		Nonce:         []byte{0xde, 0xad, 0xbe, 0xef},
		UserCallback:  userCallBackOK,
		NewSessionURI: "http://veraison.example/challenge-response/v1/newSession",
		Client:        client,
	}

	actualBody, actualSessionURI, err := cfg.newSession()

	assert.Nil(t, err)
	assert.Equal(t, expectedSessionURI, actualSessionURI)
	assert.Equal(t, expectedBody, actualBody)
}

func TestChallengeResponseConfig_check_nonce_at_least_one(t *testing.T) {
	cfg := ChallengeResponseConfig{
		UserCallback:  userCallBackOK,
		NewSessionURI: "https://veraison.example/challenge-response/v1/newSession",
	}

	err := cfg.check()
	assert.Error(t, err, "bad configuration: missing nonce info")
}

func TestChallengeResponseConfig_check_nonce_at_most_one(t *testing.T) {
	cfg := ChallengeResponseConfig{
		Nonce:         []byte{0xde, 0xad, 0xbe, 0xef},
		NonceSz:       32,
		UserCallback:  userCallBackOK,
		NewSessionURI: "https://veraison.example/challenge-response/v1/newSession",
	}

	err := cfg.check()
	assert.Error(t, err, "bad configuration: only one of nonce or nonce size must be specified")
}

func TestChallengeResponseConfig_check_callback(t *testing.T) {
	cfg := ChallengeResponseConfig{
		Nonce:         []byte{0xde, 0xad, 0xbe, 0xef},
		NewSessionURI: "https://veraison.example/challenge-response/v1/newSession",
	}

	err := cfg.check()
	assert.Error(t, err, "bad configuration: missing callback")
}

func TestChallengeResponseConfig_check_new_session_uri(t *testing.T) {
	cfg := ChallengeResponseConfig{
		Nonce:        []byte{0xde, 0xad, 0xbe, 0xef},
		UserCallback: userCallBackOK,
	}

	err := cfg.check()
	assert.Error(t, err, "bad configuration: no API endpoint")
}

func TestChallengeResponseConfig_challengeResponse_sync_ok(t *testing.T) {
	sessionBody := `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "state": "complete",
	"evidence": {
        "type": "application/psa-attestation-token",
        "value": "ZXZpZGVuY2U="
    },
	"result": {
        "is_valid": true,
		"claims": {}
    }
}`

	mediaType := "application/psa-attestation-token"
	evidence := []byte("evidence")
	sessionURI := "http://veraison.example/challenge-response/v1/session/1"

	expectedResult := `{ "is_valid": true, "claims": {} }`

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/rats-challenge-response-session+json", r.Header.Get("Accept"))
		assert.Equal(t, mediaType, r.Header.Get("Content-Type"))
		defer r.Body.Close()
		reqBody, _ := ioutil.ReadAll(r.Body)
		assert.Equal(t, evidence, reqBody)

		w.WriteHeader(http.StatusOK)
		_, e := w.Write([]byte(sessionBody))
		require.Nil(t, e)
	})

	client, teardown := newTestingHTTPClient(h)
	defer teardown()

	cfg := ChallengeResponseConfig{
		Client: client,
	}

	actualResult, err := cfg.challengeResponse(evidence, mediaType, sessionURI)

	assert.Nil(t, err)
	assert.JSONEq(t, expectedResult, string(actualResult))
}

func TestChallengeResponseConfig_deleteSession_ok(t *testing.T) {
	sessionURI := "http://veraison.example/challenge-response/v1/session/1"

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)

		w.WriteHeader(http.StatusNoContent)
	})

	client, teardown := newTestingHTTPClient(h)
	defer teardown()

	cfg := ChallengeResponseConfig{
		Client: client,
	}

	err := cfg.deleteSession(sessionURI)

	assert.Nil(t, err)
}

func TestChallengeResponseConfig_pollForAttestationResult_ok(t *testing.T) {
	sessionBody := `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "state": "complete",
	"evidence": {
        "type": "application/psa-attestation-token",
        "value": "ZXZpZGVuY2U="
    },
	"result": {
        "is_valid": true,
		"claims": {}
    }
}`

	sessionURI := "http://veraison.example/challenge-response/v1/session/1"

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)

		w.WriteHeader(http.StatusOK)
		_, e := w.Write([]byte(sessionBody))
		require.Nil(t, e)
	})

	client, teardown := newTestingHTTPClient(h)
	defer teardown()

	cfg := ChallengeResponseConfig{
		Client: client,
	}

	expectedResult := `{ "is_valid": true, "claims": {} }`

	actualResult, err := cfg.pollForAttestationResult(sessionURI)

	assert.Nil(t, err)
	assert.JSONEq(t, expectedResult, string(actualResult))
}

func TestChallengeResponseConfig_pollForAttestationResult_failed_state(t *testing.T) {
	sessionBody := `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "state": "failed",
	"evidence": {
        "type": "application/psa-attestation-token",
        "value": "ZXZpZGVuY2U="
    }
}`

	sessionURI := "http://veraison.example/challenge-response/v1/session/1"

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)

		w.WriteHeader(http.StatusOK)
		_, e := w.Write([]byte(sessionBody))
		require.Nil(t, e)
	})

	client, teardown := newTestingHTTPClient(h)
	defer teardown()

	cfg := ChallengeResponseConfig{
		Client: client,
	}

	_, err := cfg.pollForAttestationResult(sessionURI)

	assert.EqualError(t, err, "session resource in failed state")
}

func TestChallengeResponseConfig_pollForAttestationResult_unexpected_state(t *testing.T) {
	sessionBody := `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "state": "bonkers",
	"evidence": {
        "type": "application/psa-attestation-token",
        "value": "ZXZpZGVuY2U="
    }
}`

	sessionURI := "http://veraison.example/challenge-response/v1/session/1"

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)

		w.WriteHeader(http.StatusOK)
		_, e := w.Write([]byte(sessionBody))
		require.Nil(t, e)
	})

	client, teardown := newTestingHTTPClient(h)
	defer teardown()

	cfg := ChallengeResponseConfig{
		Client: client,
	}

	_, err := cfg.pollForAttestationResult(sessionURI)

	assert.EqualError(t, err, "session resource in unexpected state: bonkers")
}

func TestChallengeResponseConfig_pollForAttestationResult_exhaustion(t *testing.T) {

	sessionBody := `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "state": "processing",
	"evidence": {
        "type": "application/psa-attestation-token",
        "value": "ZXZpZGVuY2U="
    }
}`

	sessionURI := "http://veraison.example/challenge-response/v1/session/1"

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)

		w.WriteHeader(http.StatusOK)
		_, e := w.Write([]byte(sessionBody))
		require.Nil(t, e)
	})

	client, teardown := newTestingHTTPClient(h)
	defer teardown()

	cfg := ChallengeResponseConfig{
		Client: client,
	}

	_, err := cfg.pollForAttestationResult(sessionURI)

	assert.EqualError(t, err, "polling attempts exhausted, session resource state still not complete")
}
