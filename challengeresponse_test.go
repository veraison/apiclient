// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testNonce []byte = []byte{0xde, 0xad, 0xbe, 0xef}

func userCallBackOK(nonce []byte, accept []string) ([]byte, string, error) {
	return testNonce, "application/my-evidence-media-type", nil
}

// newTestingHTTPClient creates an HTTP test server (with a configurable request
// handler), an API Client and connects them together.  The API client and the
// server's shutdown switch are returned.
func newTestingHTTPClient(handler http.Handler) (*Client, func()) {
	srv := httptest.NewServer(handler)

	cli := &Client{
		HTTPClient: http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
					return net.Dial(network, srv.Listener.Addr().String())
				},
			},
		},
	}

	return cli, srv.Close
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

	expectedBody := &ChallengeResponseNewSessionResponse{
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
		w.Write([]byte(newSessionCreatedBody))
	})
	client, teardown := newTestingHTTPClient(h)
	defer teardown()

	cfg := ChallengeResponseConfig{
		Nonce:         []byte{0xde, 0xad, 0xbe, 0xef},
		Callback:      userCallBackOK,
		NewSessionURI: "http://veraison.example/challenge-response/v1/newSession",
		Client:        client,
	}

	actualBody, actualSessionURI, err := cfg.newSession()

	assert.Nil(t, err)
	assert.Equal(t, expectedSessionURI, actualSessionURI)
	assert.Equal(t, expectedBody, actualBody)
}

func TestChallengeResponseConfig_check_nonce(t *testing.T) {
	cfg := ChallengeResponseConfig{
		Callback:      userCallBackOK,
		NewSessionURI: "https://veraison.example/challenge-response/v1/newSession",
	}

	err := cfg.check()
	assert.Error(t, err, "bad configuration: missing nonce info")
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
		Nonce:    []byte{0xde, 0xad, 0xbe, 0xef},
		Callback: userCallBackOK,
	}

	err := cfg.check()
	assert.Error(t, err, "bad configuration: no API endpoint")
}
