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

var (
	testNonce    []byte = []byte{0xde, 0xad, 0xbe, 0xef}
	testEvidence []byte = []byte{0x0e, 0x0d, 0x0e}

	testBaseURI       = "http://veraison.example"
	testRelSessionURI = "/challenge-response/v1/session/1"
	testSessionURI    = testBaseURI + testRelSessionURI
	testNewSessionURI = testBaseURI + "/challenge-response/v1/newSession"
)

type testEvidenceBuilder struct{}

func (testEvidenceBuilder) BuildEvidence(
	nonce []byte,
	accept []string,
) (evidence []byte, mediaType string, err error) {
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

func TestChallengeResponseConfig_NewSession_ok(t *testing.T) {
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

	expectedSessionURI := testSessionURI

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
		Nonce:         testNonce,
		NewSessionURI: testNewSessionURI,
		Client:        client,
	}

	actualBody, actualSessionURI, err := cfg.NewSession()

	assert.Nil(t, err)
	assert.Equal(t, expectedSessionURI, actualSessionURI)
	assert.Equal(t, expectedBody, actualBody)
}

func TestChallengeResponseConfig_NewSession_server_chosen_nonce_ok(t *testing.T) {
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

	expectedSessionURI := testSessionURI

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "4", r.URL.Query().Get("nonceSize"))
		assert.Equal(t, "application/rats-challenge-response-session+json", r.Header.Get("Accept"))

		w.Header().Set("Location", expectedSessionURI)
		w.WriteHeader(http.StatusCreated)
		_, e := w.Write([]byte(newSessionCreatedBody))
		require.Nil(t, e)
	})

	client, teardown := newTestingHTTPClient(h)
	defer teardown()

	cfg := ChallengeResponseConfig{
		NonceSz:       4,
		NewSessionURI: testNewSessionURI,
		Client:        client,
	}

	actualBody, actualSessionURI, err := cfg.NewSession()

	assert.Nil(t, err)
	assert.Equal(t, expectedSessionURI, actualSessionURI)
	assert.Equal(t, expectedBody, actualBody)
}

func TestChallengeResponseConfig_NewSession_relative_location_ok(t *testing.T) {
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

	expectedSessionURI := testSessionURI
	relativeSessionURI := testRelSessionURI
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "3q2+7w==", r.URL.Query().Get("nonce"))
		assert.Equal(t, "application/rats-challenge-response-session+json", r.Header.Get("Accept"))

		w.Header().Set("Location", relativeSessionURI)
		w.WriteHeader(http.StatusCreated)
		_, e := w.Write([]byte(newSessionCreatedBody))
		require.Nil(t, e)
	})

	client, teardown := newTestingHTTPClient(h)
	defer teardown()

	cfg := ChallengeResponseConfig{
		Nonce:         testNonce,
		NewSessionURI: testNewSessionURI,
		Client:        client,
	}

	actualBody, actualSessionURI, err := cfg.NewSession()

	assert.Nil(t, err)
	assert.Equal(t, expectedSessionURI, actualSessionURI)
	assert.Equal(t, expectedBody, actualBody)
}

func TestChallengeResponseConfig_check_nonce_at_least_one(t *testing.T) {
	cfg := ChallengeResponseConfig{
		EvidenceBuilder: testEvidenceBuilder{},
		NewSessionURI:   testNewSessionURI,
	}

	for _, atomic := range []bool{true, false} {
		err := cfg.check(atomic)
		assert.EqualError(t, err, "bad configuration: missing nonce info")
	}
}

func TestChallengeResponseConfig_check_nonce_at_most_one(t *testing.T) {
	cfg := ChallengeResponseConfig{
		Nonce:           testNonce,
		NonceSz:         32,
		EvidenceBuilder: testEvidenceBuilder{},
		NewSessionURI:   testNewSessionURI,
	}

	for _, atomic := range []bool{true, false} {
		err := cfg.check(atomic)
		assert.EqualError(t, err, "bad configuration: only one of nonce or nonce size must be specified")
	}
}

func TestChallengeResponseConfig_check_evidence_builder_absence(t *testing.T) {
	cfg := ChallengeResponseConfig{
		Nonce:         testNonce,
		NewSessionURI: testNewSessionURI,
	}

	for _, atomic := range []bool{true, false} {
		err := cfg.check(atomic)
		switch atomic {
		case true:
			assert.EqualError(t, err, "bad configuration: the evidence builder is missing")
		case false:
			assert.Nil(t, err)
		}
	}
}

func TestChallengeResponseConfig_check_evidence_builder_presence(t *testing.T) {
	cfg := ChallengeResponseConfig{
		Nonce:           testNonce,
		NewSessionURI:   testNewSessionURI,
		EvidenceBuilder: testEvidenceBuilder{},
	}

	for _, atomic := range []bool{true, false} {
		err := cfg.check(atomic)
		switch atomic {
		case true:
			assert.Nil(t, err)
		case false:
			assert.EqualError(t, err, "bad configuration: found non-nil evidence builder in non-atomic mode")
		}
	}
}

func TestChallengeResponseConfig_check_new_session_uri(t *testing.T) {
	cfg := ChallengeResponseConfig{
		Nonce:           testNonce,
		EvidenceBuilder: testEvidenceBuilder{},
	}

	for _, atomic := range []bool{true, false} {
		err := cfg.check(atomic)
		assert.EqualError(t, err, "bad configuration: no API endpoint")
	}
}

func TestChallengeResponseConfig_ChallengeResponse_sync_ok(t *testing.T) {
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
	sessionURI := testSessionURI

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
		Client:        client,
		Nonce:         testNonce,
		NewSessionURI: testNewSessionURI,
	}

	actualResult, err := cfg.ChallengeResponse(evidence, mediaType, sessionURI)

	assert.Nil(t, err)
	assert.JSONEq(t, expectedResult, string(actualResult))
}

func TestChallengeResponseConfig_deleteSession_ok(t *testing.T) {
	sessionURI := testSessionURI

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

	sessionURI := testSessionURI

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

	sessionURI := testSessionURI

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

	sessionURI := testSessionURI

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

	sessionURI := testSessionURI

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

func TestChallengeResponseConfig_pollForAttestationResult_corrupted_resource(t *testing.T) {

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
}`

	sessionURI := testSessionURI

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

	assert.EqualError(t, err, "failure decoding session resource: unexpected EOF")
}

func TestChallengeResponseConfig_ChallengeResponse_bad_config_nil_client(t *testing.T) {
	cfg := ChallengeResponseConfig{
		Nonce:         testNonce,
		NewSessionURI: testNewSessionURI,
	}

	_, err := cfg.ChallengeResponse(testEvidence, "application/*", testSessionURI)

	assert.EqualError(t, err, "bad configuration: nil client")
}
