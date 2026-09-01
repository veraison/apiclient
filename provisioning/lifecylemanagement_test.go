// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package provisioning

import (
	"net/http"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/apiclient/common"
)

var (
	elmQueryMediaType = "application/vnd.veraison.elm-v1+cbor"
	testELMQuery      = []byte("test elm query")
	testActivateURI   = "http://veraison.example/endorsement-provisioning/v1/activate"
)

func TestActivateConfig_activate_check_ok(t *testing.T) {
	tv := ActivateConfig{ActivateURI: testActivateURI}

	err := tv.check()
	assert.NoError(t, err)
}

func TestActivateConfig_check_no_activate_uri(t *testing.T) {
	tv := ActivateConfig{}

	expectedErr := `bad configuration: no ELM API endpoint`

	err := tv.check()
	assert.EqualError(t, err, expectedErr)
}

func TestActivateConfig_SetActivateURI_ok(t *testing.T) {
	tv := ActivateConfig{}
	err := tv.SetActivateURI(testActivateURI)
	assert.NoError(t, err)
	assert.Equal(t, testActivateURI, tv.ActivateURI)
}

func TestActivateConfig_Run_no_elm_uri(t *testing.T) {
	tv := ActivateConfig{}

	expectedErr := `bad configuration: no ELM API endpoint`

	err := tv.Run(testELMQuery, elmQueryMediaType)
	assert.EqualError(t, err, expectedErr)
}

func TestActivateConfig_Run_fail_no_server(t *testing.T) {
	tv := ActivateConfig{ActivateURI: testActivateURI}

	err := tv.Run(testELMQuery, elmQueryMediaType)
	assert.ErrorContains(t, err, "no such host")
}

func TestActivateConfig_Run_success(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, elmQueryMediaType, r.Header.Get("Content-Type"))
		assert.Equal(t, conciseProblemMediaType, r.Header.Get("Accept"))

		w.WriteHeader(http.StatusNoContent)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := ActivateConfig{
		ActivateURI: testActivateURI,
	}
	err := cfg.SetClient(client)
	assert.NoError(t, err)

	err = cfg.Run(testELMQuery, elmQueryMediaType)
	assert.NoError(t, err)
}

func RunELMQuery_Error(t *testing.T, body []byte, status int) error {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, elmQueryMediaType, r.Header.Get("Content-Type"))
		assert.Equal(t, conciseProblemMediaType, r.Header.Get("Accept"))

		w.Header().Set("Content-Type", conciseProblemMediaType)
		w.WriteHeader(status)
		if len(body) > 0 {
			_, e := w.Write(body)
			require.Nil(t, e)
		}
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := ActivateConfig{
		ActivateURI: testActivateURI,
	}
	err := cfg.SetClient(client)
	assert.NoError(t, err)

	err = cfg.Run(testELMQuery, elmQueryMediaType)
	return err
}

func TestActivateConfig_Run_empty_body(t *testing.T) {
	err := RunELMQuery_Error(t, []byte(``), http.StatusBadRequest)
	assert.ErrorContains(t, err, "the response body is empty")
}

func TestActivateConfig_Run_decoding_failure(t *testing.T) {
	cp := "hello"
	body, err := cbor.Marshal(&cp)
	require.NoError(t, err)

	err = RunELMQuery_Error(t, body, http.StatusNotFound)
	assert.ErrorContains(t, err, "failure decoding concise error:")
}

func TestActivateConfig_Run_error(t *testing.T) {
	cp := ConciseProblem{
		Title:  "server",
		Detail: "crashed",
	}
	body, err := cbor.Marshal(&cp)
	require.NoError(t, err)

	err = RunELMQuery_Error(t, body, http.StatusInternalServerError)
	assert.EqualError(t, err, cp.Error())
}
