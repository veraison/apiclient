// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package provisioning

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/apiclient/common"
)

var (
	testEndorsement          = []byte("test corim")
	testEndorsementMediaType = "application/corim+cbor"
	testSubmitURI            = "http://veraison.example/endorsement-provisioning/v1/submit"
	testSessionURI           = "http://veraison.example/endorsement-provisioning/v1/session/1234"
)

func TestSubmitConfig_check_ok(t *testing.T) {
	tv := SubmitConfig{SubmitURI: testSubmitURI}

	err := tv.check()
	assert.NoError(t, err)
}

func TestSubmitConfig_check_no_submit_uri(t *testing.T) {
	tv := SubmitConfig{}

	expectedErr := `bad configuration: no API endpoint`

	err := tv.check()
	assert.EqualError(t, err, expectedErr)
}

func TestSubmitConfig_SetClient_ok(t *testing.T) {
	tv := SubmitConfig{}
	client := common.NewClient()
	err := tv.SetClient(client)
	assert.NoError(t, err)
}

func TestSubmitConfig_SetClient_nil_client(t *testing.T) {
	tv := SubmitConfig{}
	expectedErr := `no client supplied`
	err := tv.SetClient(nil)
	assert.EqualError(t, err, expectedErr)
}

func TestSubmitConfig_SetSubmitURI_ok(t *testing.T) {
	tv := SubmitConfig{}
	err := tv.SetSubmitURI(testSubmitURI)
	assert.NoError(t, err)
}

func TestSubmitConfig_SetSubmitURI_not_absolute(t *testing.T) {
	tv := SubmitConfig{}
	expectedErr := `uri is not absolute`
	err := tv.SetSubmitURI("veraison.example/endorsement-provisioning/v1/submit")
	assert.EqualError(t, err, expectedErr)
}

func TestSubmitConfig_Run_no_submit_uri(t *testing.T) {
	tv := SubmitConfig{}

	expectedErr := `bad configuration: no API endpoint`

	err := tv.Run(testEndorsement, testEndorsementMediaType)
	assert.EqualError(t, err, expectedErr)
}

func TestSubmitConfig_Run_fail_no_server(t *testing.T) {
	tv := SubmitConfig{SubmitURI: testSubmitURI}

	err := tv.Run(testEndorsement, testEndorsementMediaType)
	assert.ErrorContains(t, err, "no such host")
}

func TestSubmitConfig_Run_fail_404_response(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, sessionMediaType, r.Header.Get("Accept"))

		w.WriteHeader(http.StatusNotFound)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := SubmitConfig{
		SubmitURI: testSubmitURI,
		Client:    client,
	}

	expectedErr := `unexpected HTTP response code 404`

	err := cfg.Run(testEndorsement, testEndorsementMediaType)
	assert.EqualError(t, err, expectedErr)
}

func testSubmitConfigRunSyncNegative(
	t *testing.T, body []byte, expectedErr string,
) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, sessionMediaType, r.Header.Get("Accept"))

		w.Header().Set("Content-Type", sessionMediaType)
		w.WriteHeader(http.StatusOK)
		if len(body) > 0 {
			_, e := w.Write(body)
			require.Nil(t, e)
		}
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := SubmitConfig{
		SubmitURI: testSubmitURI,
		Client:    client,
	}

	err := cfg.Run(testEndorsement, testEndorsementMediaType)
	assert.EqualError(t, err, expectedErr)
}

func TestSubmitConfig_Run_fail_sync_without_session_body(t *testing.T) {
	sessionBody := ``
	expectedErr := `empty body`

	testSubmitConfigRunSyncNegative(t, []byte(sessionBody), expectedErr)
}

func TestSubmitConfig_Run_sync_failed_status(t *testing.T) {
	sessionBody := `
{
    "status": "failed",
    "expiry": "2030-10-12T07:20:50.52Z",
    "failure-reason": "taking too long"
}`
	expectedErr := `submission failed: taking too long`

	testSubmitConfigRunSyncNegative(t, []byte(sessionBody), expectedErr)
}

func TestSubmitConfig_Run_sync_unknown_status(t *testing.T) {
	sessionBody := `
{
    "status": "whatever",
    "expiry": "2030-10-12T07:20:50.52Z"
}`
	expectedErr := `unexpected session state "whatever" in 200 response`

	testSubmitConfigRunSyncNegative(t, []byte(sessionBody), expectedErr)
}

func TestSubmitConfig_Run_sync_success_status(t *testing.T) {
	sessionBody := `
{
    "status": "success",
    "expiry": "2030-10-12T07:20:50.52Z"
}`

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, sessionMediaType, r.Header.Get("Accept"))

		w.Header().Set("Content-Type", sessionMediaType)
		w.WriteHeader(http.StatusOK)
		_, e := w.Write([]byte(sessionBody))
		require.Nil(t, e)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := SubmitConfig{
		SubmitURI: testSubmitURI,
		Client:    client,
	}

	err := cfg.Run(testEndorsement, testEndorsementMediaType)
	assert.NoError(t, err)
}

func TestSubmitConfig_Run_async_fail_unexpected_status(t *testing.T) {
	sessionBody := `
{
    "status": "not processing",
    "expiry": "2030-10-12T07:20:50.52Z"
}`

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, sessionMediaType, r.Header.Get("Accept"))

		w.Header().Set("Content-Type", sessionMediaType)
		w.WriteHeader(http.StatusCreated)
		_, e := w.Write([]byte(sessionBody))
		require.Nil(t, e)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := SubmitConfig{
		SubmitURI: testSubmitURI,
		Client:    client,
	}

	expectedErr := `unexpected session state "not processing" in 201 response`

	err := cfg.Run(testEndorsement, testEndorsementMediaType)
	assert.EqualError(t, err, expectedErr)
}

func TestSubmitConfig_Run_async_fail_no_location(t *testing.T) {
	sessionBody := `
{
    "status": "processing",
    "expiry": "2030-10-12T07:20:50.52Z"
}`

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, sessionMediaType, r.Header.Get("Accept"))

		// no location header
		w.Header().Set("Content-Type", sessionMediaType)
		w.WriteHeader(http.StatusCreated)
		_, e := w.Write([]byte(sessionBody))
		require.Nil(t, e)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := SubmitConfig{
		SubmitURI: testSubmitURI,
		Client:    client,
	}

	expectedErr := `cannot determine URI for the session resource: no Location header found in response`

	err := cfg.Run(testEndorsement, testEndorsementMediaType)
	assert.EqualError(t, err, expectedErr)
}

func TestSubmitConfig_Run_async_with_delete_ok(t *testing.T) {
	sessionBody := []string{
		`{ "status": "processing", "expiry": "2030-10-12T07:20:50.52Z" }`,
		`{ "status": "success", "expiry": "2030-10-12T07:20:50.52Z" }`,
	}

	iter := 1

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch iter {
		case 1:
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, sessionMediaType, r.Header.Get("Accept"))

			w.Header().Set("Content-Type", sessionMediaType)
			w.Header().Set("Location", testSessionURI)
			w.WriteHeader(http.StatusCreated)
			_, e := w.Write([]byte(sessionBody[0]))
			require.Nil(t, e)

			iter++
		case 2:
			assert.Equal(t, http.MethodGet, r.Method)

			w.Header().Set("Content-Type", sessionMediaType)
			w.WriteHeader(http.StatusOK)
			_, e := w.Write([]byte(sessionBody[1]))
			require.Nil(t, e)

			iter++
		case 3:
			assert.Equal(t, http.MethodDelete, r.Method)

			w.WriteHeader(http.StatusOK)
		}
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := SubmitConfig{
		SubmitURI:     testSubmitURI,
		Client:        client,
		DeleteSession: true,
	}

	err := cfg.Run(testEndorsement, testEndorsementMediaType)
	assert.NoError(t, err)
}

func testSubmitConfigPollForSubmissionCompletionNegative(
	t *testing.T, responseCode int, body []byte, expectedErr string,
) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", sessionMediaType)
		w.WriteHeader(responseCode)
		if len(body) > 0 {
			_, e := w.Write(body)
			require.Nil(t, e)
		}
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := SubmitConfig{
		SubmitURI: testSubmitURI,
		Client:    client,
	}

	err := cfg.pollForSubmissionCompletion(testSessionURI)
	assert.EqualError(t, err, expectedErr)
}

func TestSubmitConfig_pollForSubmissionCompletion_fail_not_found(t *testing.T) {
	sessionBody := ``
	responseCode := http.StatusNotFound
	expectedErr := `session resource fetch returned an unexpected status: 404 Not Found`

	testSubmitConfigPollForSubmissionCompletionNegative(
		t, responseCode, []byte(sessionBody), expectedErr,
	)
}

func TestSubmitConfig_pollForSubmissionCompletion_fail_invalid_session_resource(t *testing.T) {
	sessionBody := `invalid json`
	responseCode := http.StatusOK
	expectedErr := `failure decoding session resource: invalid character 'i' looking for beginning of value`

	testSubmitConfigPollForSubmissionCompletionNegative(
		t, responseCode, []byte(sessionBody), expectedErr,
	)
}

func TestSubmitConfig_pollForSubmissionCompletion_failed_status(t *testing.T) {
	sessionBody := `
{
    "status": "failed",
    "expiry": "2030-10-12T07:20:50.52Z",
    "failure-reason": "server too cold"
}`
	responseCode := http.StatusOK
	expectedErr := `submission failed: server too cold`

	testSubmitConfigPollForSubmissionCompletionNegative(
		t, responseCode, []byte(sessionBody), expectedErr,
	)
}

func TestSubmitConfig_pollForSubmissionCompletion_success_status(t *testing.T) {
	sessionBody := `
{
    "status": "random",
    "expiry": "2030-10-12T07:20:50.52Z"
}`
	responseCode := http.StatusOK
	expectedErr := `unexpected session state "random" in 200 response`

	testSubmitConfigPollForSubmissionCompletionNegative(
		t, responseCode, []byte(sessionBody), expectedErr,
	)
}
