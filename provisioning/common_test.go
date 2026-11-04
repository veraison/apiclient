// Copyright 2021-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package provisioning

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/apiclient/auth"
	"github.com/veraison/apiclient/common"
)

var (
	testCertPaths = []string{"/test/path1", "/test/path2"}
)

func TestCommonConfig_SetClient_ok(t *testing.T) {
	tv := CommonConfig{}
	client := common.NewClient(nil)
	err := tv.SetClient(client)
	assert.NoError(t, err)
}

func TestCommonConfig_SetClient_nil_client(t *testing.T) {
	tv := CommonConfig{}
	expectedErr := `no client supplied`
	err := tv.SetClient(nil)
	assert.EqualError(t, err, expectedErr)
}

func TestCommonConfig_initClient(t *testing.T) {
	cfg := CommonConfig{}
	require.NoError(t, cfg.initClient())
	assert.Nil(t, cfg.client.HTTPClient.Transport)

	cfg = CommonConfig{useTLS: true}
	require.NoError(t, cfg.initClient())
	require.NotNil(t, cfg.client.HTTPClient.Transport)
	transport := cfg.client.HTTPClient.Transport.(*http.Transport)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)

	cfg = CommonConfig{useTLS: true, isInsecure: true}
	require.NoError(t, cfg.initClient())
	require.NotNil(t, cfg.client.HTTPClient.Transport)
	transport = cfg.client.HTTPClient.Transport.(*http.Transport)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestCommonConfig_setters(t *testing.T) {
	cfg := CommonConfig{}
	require.NoError(t, cfg.initClient())

	a := &auth.NullAuthenticator{}
	cfg.SetAuth(a)
	assert.Equal(t, a, cfg.auth)
	assert.Equal(t, a, cfg.client.Auth)

	cfg.SetIsInsecure(true)
	assert.True(t, cfg.isInsecure)

	cfg.SetCerts(testCertPaths)
	assert.EqualValues(t, testCertPaths, cfg.caCerts)
}

func TestProvisioning_checkURI_not_absolute(t *testing.T) {
	expectedErr := `uri is not absolute`
	_, err := checkURI("veraison.example/endorsement-provisioning/v1/submit")
	assert.EqualError(t, err, expectedErr)
}

func TestProvisioning_checkURI_scheme(t *testing.T) {
	expectedErr := `unknown scheme: ftp, only http and https are supported`
	_, err := checkURI("ftp://good")
	assert.ErrorContains(t, err, expectedErr)
}

func TestProvisioning_checkURI_malformed(t *testing.T) {
	expectedErr := `malformed URI`
	_, err := checkURI("://invalid")
	assert.ErrorContains(t, err, expectedErr)
}
