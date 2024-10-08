// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/apiclient/common"
)

var (
	testNonce         []byte = []byte{0xde, 0xad, 0xbe, 0xef}
	testNonceSz       uint   = 32
	testEvidence      []byte = []byte{0x0e, 0x0d, 0x0e}
	testCMWEvCBOR     []byte = []byte{0x83, 0x78, 0x22, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6d, 0x79, 0x2d, 0x65, 0x76, 0x69, 0x64, 0x65, 0x6e, 0x63, 0x65, 0x2d, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x43, 0x0e, 0x0d, 0x0e, 0x04}
	testCMWCtCBOR     string = "application/vnd.veraison.cmw+cbor"
	testCMWEvJSON     []byte = []byte(`["application/my-evidence-media-type","Dg0O",4]`)
	testCMWCtJSON     string = "application/vnd.veraison.cmw+json"
	testBaseURI              = "http://veraison.example"
	testRelSessionURI        = "/challenge-response/v1/session/1"
	testSessionURI           = testBaseURI + testRelSessionURI
	testNewSessionURI        = testBaseURI + "/challenge-response/v1/newSession"
	testBadURI               = `http://veraison.example:80challenge-response/v1/session/1`
	testCertPaths            = []string{"/test/path1", "/test/path2"}
)

type testEvidenceBuilder struct{}

func (testEvidenceBuilder) BuildEvidence(
	nonce []byte,
	accept []string,
) (evidence []byte, mediaType string, err error) {
	return testEvidence, "application/my-evidence-media-type", nil
}

func TestChallengeResponseConfig_SetNonce_ok(t *testing.T) {
	cfg := ChallengeResponseConfig{}
	err := cfg.SetNonce(testNonce)
	assert.NoError(t, err)
}

func TestChallengeResponseConfig_SetNonce_nil_nonce(t *testing.T) {
	cfg := ChallengeResponseConfig{}
	expectedErr := `no nonce supplied`
	var nonce []byte
	err := cfg.SetNonce(nonce)
	assert.EqualError(t, err, expectedErr)
}

func TestChallengeResponseConfig_SetNonceSz_ok(t *testing.T) {
	cfg := ChallengeResponseConfig{}
	err := cfg.SetNonceSz(testNonceSz)
	assert.NoError(t, err)
}

func TestChallengeResponseConfig_SetNonceSz_zero_noncesz(t *testing.T) {
	cfg := ChallengeResponseConfig{}
	expectedErr := `zero nonce size supplied`
	err := cfg.SetNonceSz(0)
	assert.EqualError(t, err, expectedErr)
}
func TestChallengeResponseConfig_SetClient_ok(t *testing.T) {
	cfg := ChallengeResponseConfig{}
	client := common.NewClient(nil)
	err := cfg.SetClient(client)
	assert.NoError(t, err)
}

func TestChallengeResponseConfig_SetClient_nil_client(t *testing.T) {
	cfg := ChallengeResponseConfig{}
	expectedErr := `no client supplied`
	err := cfg.SetClient(nil)
	assert.EqualError(t, err, expectedErr)
}

func TestChallengeResponseConfig_SetSessionURI_ok(t *testing.T) {
	cfg := ChallengeResponseConfig{}
	err := cfg.SetSessionURI(testSessionURI)
	assert.NoError(t, err)
}

func TestChallengeResponseConfig_SetSessionURI_not_absolute(t *testing.T) {
	cfg := ChallengeResponseConfig{}
	expectedErr := `the supplied session URI is not in absolute form`
	err := cfg.SetSessionURI("veraison.example/challenge-response/v1/session/1")
	assert.EqualError(t, err, expectedErr)
}

func TestChallengeResponseConfig_SetSessionURI_bad_uri(t *testing.T) {
	cfg := ChallengeResponseConfig{}
	expectedErr := `malformed session URI: parse "http://veraison.example:80challenge-response/v1/session/1": invalid port ":80challenge-response" after host`
	err := cfg.SetSessionURI(testBadURI)
	assert.EqualError(t, err, expectedErr)
}

func TestChallengeResponseConfig_SetEvidenceBuilder_ok(t *testing.T) {
	cfg := ChallengeResponseConfig{}
	err := cfg.SetEvidenceBuilder(testEvidenceBuilder{})
	assert.NoError(t, err)
}

func TestChallengeResponseConfig_SetEvidenceBuilder_no_ok(t *testing.T) {
	cfg := ChallengeResponseConfig{}
	expectedErr := `no evidence builder supplied`
	err := cfg.SetEvidenceBuilder(nil)
	assert.EqualError(t, err, expectedErr)
}

func TestChallengeResponseConfig_NewSession_ok(t *testing.T) {
	newSessionCreatedBody := `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "status": "waiting"
}`

	expectedBody := &ChallengeResponseSession{
		Nonce:  testNonce,
		Expiry: "2030-10-12T07:20:50.52Z",
		Accept: []string{
			"application/psa-attestation-token",
		},
		Status: "waiting",
	}

	expectedSessionURI := testSessionURI

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "3q2-7w==", r.URL.Query().Get("nonce"))
		assert.Equal(t, "application/vnd.veraison.challenge-response-session+json", r.Header.Get("Accept"))

		w.Header().Set("Location", expectedSessionURI)
		w.WriteHeader(http.StatusCreated)
		_, e := w.Write([]byte(newSessionCreatedBody))
		require.Nil(t, e)
	})

	client, teardown := common.NewTestingHTTPClient(h)
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

func TestChallengeResponseConfig_SetCMWWrap_ok(t *testing.T) {
	cfg := ChallengeResponseConfig{}
	err := cfg.SetWrap(WrapCBOR)
	assert.NoError(t, err)
	err = cfg.SetWrap(WrapJSON)
	assert.NoError(t, err)
}

func TestChallengeResponseConfig_SetCMWWrap_nok(t *testing.T) {
	cfg := ChallengeResponseConfig{}
	randomWrap := 57
	expectedErr := "invalid CMW Wrap: 57"
	err := cfg.SetWrap(CmwWrap(randomWrap))
	assert.EqualError(t, err, expectedErr)
}

func TestChallengeResponseConfig_NewSession_server_chosen_nonce_ok(t *testing.T) {
	newSessionCreatedBody := `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "status": "waiting"
}`

	expectedBody := &ChallengeResponseSession{
		Nonce:  testNonce,
		Expiry: "2030-10-12T07:20:50.52Z",
		Accept: []string{
			"application/psa-attestation-token",
		},
		Status: "waiting",
	}

	expectedSessionURI := testSessionURI

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "4", r.URL.Query().Get("nonceSize"))
		assert.Equal(t, "application/vnd.veraison.challenge-response-session+json", r.Header.Get("Accept"))

		w.Header().Set("Location", expectedSessionURI)
		w.WriteHeader(http.StatusCreated)
		_, e := w.Write([]byte(newSessionCreatedBody))
		require.Nil(t, e)
	})

	client, teardown := common.NewTestingHTTPClient(h)
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
	"status": "waiting"
}`

	expectedBody := &ChallengeResponseSession{
		Nonce:  testNonce,
		Expiry: "2030-10-12T07:20:50.52Z",
		Accept: []string{
			"application/psa-attestation-token",
		},
		Status: "waiting",
	}

	expectedSessionURI := testSessionURI
	relativeSessionURI := testRelSessionURI
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "3q2-7w==", r.URL.Query().Get("nonce"))
		assert.Equal(t, "application/vnd.veraison.challenge-response-session+json", r.Header.Get("Accept"))

		w.Header().Set("Location", relativeSessionURI)
		w.WriteHeader(http.StatusCreated)
		_, e := w.Write([]byte(newSessionCreatedBody))
		require.Nil(t, e)
	})

	client, teardown := common.NewTestingHTTPClient(h)
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
    "status": "complete",
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
		assert.Equal(t, "application/vnd.veraison.challenge-response-session+json", r.Header.Get("Accept"))
		assert.Equal(t, mediaType, r.Header.Get("Content-Type"))
		defer r.Body.Close()
		reqBody, _ := io.ReadAll(r.Body)
		assert.Equal(t, evidence, reqBody)

		w.WriteHeader(http.StatusOK)
		_, e := w.Write([]byte(sessionBody))
		require.Nil(t, e)
	})

	client, teardown := common.NewTestingHTTPClient(h)
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

func TestChallengeResponseConfig_pollForAttestationResult_ok(t *testing.T) {
	sessionBody := `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "status": "complete",
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

	client, teardown := common.NewTestingHTTPClient(h)
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
    "status": "failed",
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

	client, teardown := common.NewTestingHTTPClient(h)
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
    "status": "bonkers",
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

	client, teardown := common.NewTestingHTTPClient(h)
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
    "status": "processing",
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

	client, teardown := common.NewTestingHTTPClient(h)
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
    "status": "processing",
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

	client, teardown := common.NewTestingHTTPClient(h)
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

func TestChallengeResponseConfig_Run_async_ok(t *testing.T) {
	sessionState := []string{`
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "status": "waiting"
}`, `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "status": "processing",
	"evidence": {
        "type": "application/psa-attestation-token",
        "value": "ZXZpZGVuY2U="
    }
}`, `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "status": "complete",
	"evidence": {
        "type": "application/psa-attestation-token",
        "value": "ZXZpZGVuY2U="
    },
	"result": {
        "is_valid": true,
		"claims": {}
    }
}`,
	}

	iter := 1

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch iter {
		case 1:
			assert.Equal(t, http.MethodPost, r.Method)

			w.Header().Set("Location", testRelSessionURI)
			w.WriteHeader(http.StatusCreated)
			_, e := w.Write([]byte(sessionState[0]))
			require.Nil(t, e)

			iter++
		case 2:
			assert.Equal(t, http.MethodPost, r.Method)

			w.WriteHeader(http.StatusAccepted)
			_, e := w.Write([]byte(sessionState[1]))
			require.Nil(t, e)

			iter++
		case 3:
			assert.Equal(t, http.MethodGet, r.Method)

			w.WriteHeader(http.StatusOK)
			_, e := w.Write([]byte(sessionState[2]))
			require.Nil(t, e)
		}
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := ChallengeResponseConfig{
		Nonce:           testNonce,
		NewSessionURI:   testNewSessionURI,
		EvidenceBuilder: testEvidenceBuilder{},
		Client:          client,
	}

	expectedResult := `{ "is_valid": true, "claims": {} }`

	result, err := cfg.Run()

	assert.NoError(t, err)
	assert.JSONEq(t, expectedResult, string(result))
}

func TestChallengeResponseConfig_Run_async_with_explicit_delete_failed(t *testing.T) {
	sessionState := []string{`
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "status": "waiting"
}`, `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "status": "processing",
    "evidence": {
        "type": "application/psa-attestation-token",
        "value": "ZXZpZGVuY2U="
    }
}`, `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "status": "failed",
    "evidence": {
        "type": "application/psa-attestation-token",
        "value": "ZXZpZGVuY2U="
    }
}`,
	}

	iter := 1

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch iter {
		case 1:
			assert.Equal(t, http.MethodPost, r.Method)

			w.Header().Set("Location", testRelSessionURI)
			w.WriteHeader(http.StatusCreated)
			_, e := w.Write([]byte(sessionState[0]))
			require.Nil(t, e)

			iter++
		case 2:
			assert.Equal(t, http.MethodPost, r.Method)

			w.WriteHeader(http.StatusAccepted)
			_, e := w.Write([]byte(sessionState[1]))
			require.Nil(t, e)

			iter++
		case 3:
			assert.Equal(t, http.MethodGet, r.Method)

			w.WriteHeader(http.StatusOK)
			_, e := w.Write([]byte(sessionState[2]))
			require.Nil(t, e)

			iter++
		case 4:
			assert.Equal(t, http.MethodDelete, r.Method)

			w.WriteHeader(http.StatusOK)
		}
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := ChallengeResponseConfig{
		Nonce:           testNonce,
		NewSessionURI:   testNewSessionURI,
		EvidenceBuilder: testEvidenceBuilder{},
		Client:          client,
		DeleteSession:   true,
	}

	result, err := cfg.Run()

	assert.EqualError(t, err, "session resource in failed state")
	assert.Nil(t, result)
}

func synthesizeSession(mt string, ev []byte) []string {
	s := []string{`
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "status": "waiting"
}`, `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "status": "processing",
	"evidence": {
        "type": "%s",
        "value": "%s"
    }
}`, `
{
    "nonce": "3q2+7w==",
    "expiry": "2030-10-12T07:20:50.52Z",
    "accept": [
        "application/psa-attestation-token"
    ],
    "status": "complete",
	"evidence": {
        "type": "application/vnd.parallaxsecond.key-attestation.tpm",
        "value": "%s"
    },
	"result": {
        "is_valid": true,
		"claims": {}
    }
}`,
	}
	evs := base64.URLEncoding.EncodeToString(ev)
	s[1] = fmt.Sprintf(s[1], mt, evs)
	s[2] = fmt.Sprintf(s[2], evs)
	return s
}

func TestChallengeResponseConfig_Run_async_CMWWrap(t *testing.T) {
	tvs := []struct {
		desc         string
		wrap         CmwWrap
		ct           string
		ev           []byte
		sessionState []string
	}{
		{
			desc:         "test CBOR",
			wrap:         WrapCBOR,
			ct:           testCMWCtCBOR,
			ev:           testCMWEvCBOR,
			sessionState: synthesizeSession(testCMWCtCBOR, testCMWEvCBOR),
		},
		{
			desc:         "test JSON",
			wrap:         WrapJSON,
			ct:           testCMWCtJSON,
			ev:           testCMWEvJSON,
			sessionState: synthesizeSession(testCMWCtJSON, testCMWEvJSON),
		},
	}
	for _, tv := range tvs {
		iter := 1
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch iter {
			case 1:
				assert.Equal(t, http.MethodPost, r.Method)
				w.Header().Set("Location", testRelSessionURI)
				w.WriteHeader(http.StatusCreated)
				_, e := w.Write([]byte(tv.sessionState[0]))
				require.Nil(t, e)

				iter++
			case 2:
				assert.Equal(t, http.MethodPost, r.Method)
				ev, err := io.ReadAll(r.Body)
				require.Nil(t, err)
				assert.Equal(t, ev, tv.ev)
				assert.Equal(t, r.Header.Get("Content-Type"), tv.ct)
				w.WriteHeader(http.StatusAccepted)
				_, e := w.Write([]byte(tv.sessionState[1]))
				require.Nil(t, e)

				iter++
			case 3:
				assert.Equal(t, http.MethodGet, r.Method)

				w.WriteHeader(http.StatusOK)
				_, e := w.Write([]byte(tv.sessionState[2]))
				require.Nil(t, e)
			}
		})

		client, teardown := common.NewTestingHTTPClient(h)
		defer teardown()
		cfg := ChallengeResponseConfig{
			Nonce:           testNonce,
			NewSessionURI:   testNewSessionURI,
			EvidenceBuilder: testEvidenceBuilder{},
			Client:          client,
			Wrap:            tv.wrap,
		}
		expectedResult := `{ "is_valid": true, "claims": {} }`

		result, err := cfg.Run()
		assert.NoError(t, err)
		assert.JSONEq(t, expectedResult, string(result))
	}
}

func TestChallengeResponseConfig_initClient(t *testing.T) {
	cfg := ChallengeResponseConfig{NewSessionURI: testNewSessionURI}
	require.NoError(t, cfg.initClient())
	assert.Nil(t, cfg.Client.HTTPClient.Transport)

	cfg = ChallengeResponseConfig{NewSessionURI: testNewSessionURI, UseTLS: true}
	require.NoError(t, cfg.initClient())
	require.NotNil(t, cfg.Client.HTTPClient.Transport)
	transport := cfg.Client.HTTPClient.Transport.(*http.Transport)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)

	cfg = ChallengeResponseConfig{
		NewSessionURI: testNewSessionURI,
		UseTLS:        true,
		IsInsecure:    true,
	}
	assert.NoError(t, cfg.initClient())
	require.NotNil(t, cfg.Client.HTTPClient.Transport)
	transport = cfg.Client.HTTPClient.Transport.(*http.Transport)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestChallengeResponseConfig_setters(t *testing.T) {
	cfg := ChallengeResponseConfig{NewSessionURI: testNewSessionURI}
	require.NoError(t, cfg.initClient())

	cfg.SetDeleteSession(true)
	assert.True(t, cfg.DeleteSession)

	cfg.SetIsInsecure(true)
	assert.True(t, cfg.IsInsecure)

	cfg.SetCerts(testCertPaths)
	assert.EqualValues(t, testCertPaths, cfg.CACerts)
}
