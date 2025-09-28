// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package provisioning

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/apiclient/auth"
	"github.com/veraison/apiclient/common"
)

var (
	testEndorsement          = []byte("test corim")
	testEndorsementMediaType = "application/corim+cbor"
	testSubmitURI            = "http://veraison.example/endorsement-provisioning/v1/submit"
	testSessionURI           = "http://veraison.example/endorsement-provisioning/v1/session/1234"
	testCertPaths            = []string{"/test/path1", "/test/path2"}
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
	client := common.NewClient(nil)
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

	session, err := tv.Run(testEndorsement, testEndorsementMediaType)
	assert.EqualError(t, err, expectedErr)
	assert.Nil(t, session)
}

func TestSubmitConfig_Run_fail_no_server(t *testing.T) {
	tv := SubmitConfig{SubmitURI: testSubmitURI}

	session, err := tv.Run(testEndorsement, testEndorsementMediaType)
	assert.ErrorContains(t, err, "no such host")
	assert.Nil(t, session)
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

	session, err := cfg.Run(testEndorsement, testEndorsementMediaType)
	assert.EqualError(t, err, expectedErr)
	assert.Nil(t, session)
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

	session, err := cfg.Run(testEndorsement, testEndorsementMediaType)
	assert.EqualError(t, err, expectedErr)
	assert.Nil(t, session)
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

	session, err := cfg.Run(testEndorsement, testEndorsementMediaType)
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "success", session.Status)
	assert.Equal(t, "2030-10-12T07:20:50.52Z", session.Expiry)
}

func TestSubmitConfig_Run_success_info_returned(t *testing.T) {
	// This test specifically demonstrates the fix for GitHub issue #14:
	// "Investigate whether Provisioning API Client Return Code on Success"
	// The Run method now returns SubmitSession with success details that
	// can be displayed to users upon successful CoRIM submission.
	sessionBody := `
{
    "status": "success",
    "expiry": "2030-12-25T10:30:45.123Z"
}`

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, sessionMediaType, r.Header.Get("Accept"))
		assert.Equal(t, testEndorsementMediaType, r.Header.Get("Content-Type"))

		// Verify the CoRIM payload was sent
		defer r.Body.Close()
		reqBody, _ := io.ReadAll(r.Body)
		assert.Equal(t, testEndorsement, reqBody)

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

	// The key improvement: Run now returns success information that can be displayed
	session, err := cfg.Run(testEndorsement, testEndorsementMediaType)

	// Verify success
	assert.NoError(t, err)
	require.NotNil(t, session)

	// Verify success details that can be displayed to users
	assert.Equal(t, "success", session.Status)
	assert.Equal(t, "2030-12-25T10:30:45.123Z", session.Expiry)
	assert.Nil(t, session.FailureReason)

	// Example of how users can now display success information
	t.Logf("CoRIM successfully submitted! Status: %s, Expires: %s", session.Status, session.Expiry)
}

func TestSubmitConfig_Run_async_success_info_returned(t *testing.T) {
	// This test demonstrates the fix for GitHub issue #14 in async scenarios:
	// The Run method returns SubmitSession with success details even after polling.
	sessionBodies := []string{
		`{ "status": "processing", "expiry": "2030-12-25T10:30:45.123Z" }`,
		`{ "status": "success", "expiry": "2030-12-25T10:30:45.123Z" }`,
	}

	iter := 1
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch iter {
		case 1:
			assert.Equal(t, http.MethodPost, r.Method)
			w.Header().Set("Content-Type", sessionMediaType)
			w.Header().Set("Location", testSessionURI)
			w.WriteHeader(http.StatusCreated)
			_, e := w.Write([]byte(sessionBodies[0]))
			require.Nil(t, e)
			iter++
		case 2:
			assert.Equal(t, http.MethodGet, r.Method)
			w.Header().Set("Content-Type", sessionMediaType)
			w.WriteHeader(http.StatusOK)
			_, e := w.Write([]byte(sessionBodies[1]))
			require.Nil(t, e)
		}
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := SubmitConfig{
		SubmitURI: testSubmitURI,
		Client:    client,
	}

	// The key improvement: Run returns success information even for async operations
	session, err := cfg.Run(testEndorsement, testEndorsementMediaType)

	// Verify success
	assert.NoError(t, err)
	require.NotNil(t, session)

	// Verify success details that can be displayed to users after async polling
	assert.Equal(t, "success", session.Status)
	assert.Equal(t, "2030-12-25T10:30:45.123Z", session.Expiry)
	assert.Nil(t, session.FailureReason)

	// Example of async success information display
	t.Logf("CoRIM async submission completed! Status: %s, Expires: %s", session.Status, session.Expiry)
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

	session, err := cfg.Run(testEndorsement, testEndorsementMediaType)
	assert.EqualError(t, err, expectedErr)
	assert.Nil(t, session)
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

	session, err := cfg.Run(testEndorsement, testEndorsementMediaType)
	assert.EqualError(t, err, expectedErr)
	assert.Nil(t, session)
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

	session, err := cfg.Run(testEndorsement, testEndorsementMediaType)
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "success", session.Status)
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

	session, err := cfg.pollForSubmissionCompletion(testSessionURI)
	assert.EqualError(t, err, expectedErr)
	assert.Nil(t, session)
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

func TestSubmitConfig_initClient(t *testing.T) {
	cfg := SubmitConfig{SubmitURI: testSubmitURI}
	require.NoError(t, cfg.initClient())
	assert.Nil(t, cfg.Client.HTTPClient.Transport)

	cfg = SubmitConfig{SubmitURI: testSubmitURI, UseTLS: true}
	require.NoError(t, cfg.initClient())
	require.NotNil(t, cfg.Client.HTTPClient.Transport)
	transport := cfg.Client.HTTPClient.Transport.(*http.Transport)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)

	cfg = SubmitConfig{SubmitURI: testSubmitURI, UseTLS: true, IsInsecure: true}
	require.NoError(t, cfg.initClient())
	require.NotNil(t, cfg.Client.HTTPClient.Transport)
	transport = cfg.Client.HTTPClient.Transport.(*http.Transport)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestSubmitConfig_setters(t *testing.T) {
	cfg := SubmitConfig{SubmitURI: testSubmitURI}
	require.NoError(t, cfg.initClient())

	cfg.SetDeleteSession(true)
	assert.True(t, cfg.DeleteSession)

	a := &auth.NullAuthenticator{}
	cfg.SetAuth(a)
	assert.Equal(t, a, cfg.Auth)
	assert.Equal(t, a, cfg.Client.Auth)

	cfg.SetIsInsecure(true)
	assert.True(t, cfg.IsInsecure)

	cfg.SetCerts(testCertPaths)
	assert.EqualValues(t, testCertPaths, cfg.CACerts)
}
