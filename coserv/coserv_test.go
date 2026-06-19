// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package coserv

import (
	"crypto/ecdsa"
	"crypto/rand"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/apiclient/auth"
	"github.com/veraison/apiclient/common"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/coserv"
	"github.com/veraison/eat"
	"github.com/veraison/go-cose"
	"github.com/yosida95/uritemplate/v3"
)

var (
	testRequestResponseURI = "http://veraison.example/endorsement-distribution/v1/coserv/{query}"
	testCACerts            = []string{"/test/ca1.pem", "/test/ca2.pem"}

	testES256KeyJWK = `{
		"kty": "EC",
		"crv": "P-256",
		"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
	}`
)

// newDefaultQuery returns a fresh, valid CoSERV query.
func newDefaultQuery() *coserv.Coserv {
	profile, err := eat.NewProfile("tag:example.com,2025:cc-platform#1.0.0")
	if err != nil {
		panic(err)
	}
	class := comid.NewClassBytes([]byte{0x00, 0x11, 0x22, 0x33})
	class.SetVendor("ACME").SetModel("ARM CCA")
	envSelector := coserv.NewEnvironmentSelector()
	envSelector.AddClass(coserv.StatefulClass{Class: class})
	queryStruct := coserv.Query{
		ArtifactType:        coserv.ArtifactTypeReferenceValues,
		EnvironmentSelector: *envSelector,
		ResultType:          coserv.ResultTypeBoth,
	}
	return &coserv.Coserv{Profile: *profile, Query: queryStruct}
}

// newDefaultResponse returns a fresh, valid CoSERV response.
func newDefaultResponse() *coserv.Coserv {
	query := newDefaultQuery()
	return &coserv.Coserv{
		Profile: query.Profile,
		Query:   query.Query,
		Results: coserv.NewResultSet().
			SetExpiry(time.Now().Add(24 * time.Hour)).
			AddReferenceValues(coserv.RefValQuad{}),
	}
}

// getSignerAndVerifierFromJWK loads a fixed JWK and returns a signer and verifier.
func getSignerAndVerifierFromJWK(jwkJSON string) (cose.Signer, cose.Verifier, error) {
	keySet, kerr := jwk.Parse([]byte(jwkJSON))
	if kerr != nil {
		return nil, nil, kerr
	}
	key, ok := keySet.Key(0)
	if !ok {
		return nil, nil, kerr
	}
	var ecdsaPriv ecdsa.PrivateKey
	if err := key.Raw(&ecdsaPriv); err != nil {
		return nil, nil, err
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, &ecdsaPriv)
	if err != nil {
		return nil, nil, err
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, &ecdsaPriv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return signer, verifier, nil
}

// signResponse signs the given CoSERV response with the fixed valid key.
func signResponse(resp *coserv.Coserv) ([]byte, cose.Verifier, error) {
	signer, verifier, err := getSignerAndVerifierFromJWK(testES256KeyJWK)
	if err != nil {
		return nil, nil, err
	}
	msg, serr := resp.Sign(signer)
	if serr != nil {
		return nil, nil, serr
	}
	return msg, verifier, nil
}

func TestQueryConfig_check_ok(t *testing.T) {
	tpl, err := uritemplate.New(testRequestResponseURI)
	assert.NoError(t, err)
	cfg := QueryConfig{RequestResponseURI: tpl}
	err = cfg.check()
	assert.NoError(t, err)
}

func TestQueryConfig_check_no_url(t *testing.T) {
	cfg := QueryConfig{}
	err := cfg.check()
	assert.EqualError(t, err, "bad configuration: no request-response URL template")
}

func TestQueryConfig_SetClient_ok(t *testing.T) {
	cfg := QueryConfig{}
	client := common.NewClient(nil)
	err := cfg.SetClient(client)
	assert.NoError(t, err)
	assert.Equal(t, client, cfg.Client)
}

func TestQueryConfig_SetClient_WithAuth(t *testing.T) {
	cfg := QueryConfig{}
	authMock := &auth.NullAuthenticator{}
	cfg.SetAuth(authMock)
	client := common.NewClient(nil)
	err := cfg.SetClient(client)
	assert.NoError(t, err)
	assert.Equal(t, authMock, cfg.Client.Auth)
}

func TestQueryConfig_SetClient_nil(t *testing.T) {
	cfg := QueryConfig{}
	err := cfg.SetClient(nil)
	assert.EqualError(t, err, "no client supplied")
}

func TestQueryConfig_SetRequestResponseURI_ok(t *testing.T) {
	cfg := QueryConfig{}
	err := cfg.SetRequestResponseURI(testRequestResponseURI)
	assert.NoError(t, err)
	tpl, err := uritemplate.New(testRequestResponseURI)
	assert.NoError(t, err)
	assert.Equal(t, tpl.Regexp().String(), cfg.RequestResponseURI.Regexp().String())
	assert.False(t, cfg.UseTLS)
}

func TestQueryConfig_SetRequestResponseURI_malformed(t *testing.T) {
	cfg := QueryConfig{}
	err := cfg.SetRequestResponseURI("://invalid")
	assert.ErrorContains(t, err, "malformed URI")
}

func TestQueryConfig_SetRequestResponseURI_malformed_in_between(t *testing.T) {
	cfg := QueryConfig{}
	err := cfg.SetRequestResponseURI("https://coserv/{query}/endpoint")
	assert.EqualError(t, err, "URI template must end with '{query}'")
}

func TestQueryConfig_SetRequestResponseURI_not_absolute(t *testing.T) {
	cfg := QueryConfig{}
	err := cfg.SetRequestResponseURI("/coserv/{query}")
	assert.EqualError(t, err, "URI is not absolute")
}

func TestQueryConfig_SetRequestResponseURI_missing_placeholder(t *testing.T) {
	cfg := QueryConfig{}
	err := cfg.SetRequestResponseURI("https://example.com/coserv")
	assert.EqualError(t, err, "URI template must end with '{query}'")
}

func TestQueryConfig_SetAuth(t *testing.T) {
	cfg := QueryConfig{}
	authMock := &auth.NullAuthenticator{}
	cfg.SetAuth(authMock)
	assert.Equal(t, authMock, cfg.Auth)

	client := common.NewClient(nil)
	cfg.Client = client
	cfg.SetAuth(authMock)
	assert.Equal(t, authMock, cfg.Client.Auth)
}

func TestQueryConfig_SetIsInsecure(t *testing.T) {
	cfg := QueryConfig{}
	cfg.SetIsInsecure(true)
	assert.True(t, cfg.IsInsecure)
}

func TestQueryConfig_EnableCache(t *testing.T) {
	cfg := QueryConfig{}
	assert.False(t, cfg.Cache)
	cfg.EnableCache(true)
	assert.True(t, cfg.Cache)
}

func TestQueryConfig_SetCerts(t *testing.T) {
	cfg := QueryConfig{}
	_ = cfg.SetCerts(testCACerts)
	assert.EqualValues(t, testCACerts, cfg.CACerts)
}

func TestQueryConfig_initClient_no_tls(t *testing.T) {
	cfg := QueryConfig{}
	err := cfg.initClient()
	assert.NoError(t, err)
	assert.NotNil(t, cfg.Client)
	assert.Nil(t, cfg.Client.HTTPClient.Transport)
}

func TestQueryConfig_initClient_tls_insecure(t *testing.T) {
	cfg := QueryConfig{
		UseTLS:     true,
		IsInsecure: true,
	}
	err := cfg.initClient()
	assert.NoError(t, err)
	assert.NotNil(t, cfg.Client)
	tr, ok := cfg.Client.HTTPClient.Transport.(*http.Transport)
	assert.True(t, ok)
	assert.True(t, tr.TLSClientConfig.InsecureSkipVerify)
}

func TestQueryConfig_initClient_already_set(t *testing.T) {
	customClient := common.NewClient(nil)
	cfg := QueryConfig{Client: customClient}
	err := cfg.initClient()
	assert.NoError(t, err)
	assert.Equal(t, customClient, cfg.Client)
}

func TestQueryConfig_initClient_with_cache(t *testing.T) {
	cfg := QueryConfig{
		Cache: true,
	}
	err := cfg.initClient()
	assert.NoError(t, err)
	assert.NotNil(t, cfg.Client)
	_, ok := cfg.Client.HTTPClient.Transport.(*cachedTransport)
	assert.True(t, ok)
}

func TestAddCache(t *testing.T) {
	err := addCache(nil)
	assert.EqualError(t, err, "failed to add cache layer, client is empty")
	customClient := common.NewClient(nil)
	err = addCache(customClient)
	assert.NoError(t, err)
	_, ok := customClient.HTTPClient.Transport.(*cachedTransport)
	assert.True(t, ok)
}

func TestQueryConfig_RunQueryForUnsignedResponse_Success(t *testing.T) {
	respCBOR, err := newDefaultResponse().ToCBOR()
	require.NoError(t, err)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, UnsignedCoSERVMediaType, r.Header.Get("Accept"))
		w.Header().Set("Content-Type", UnsignedCoSERVMediaType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respCBOR)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := QueryConfig{}
	err = cfg.SetRequestResponseURI(testRequestResponseURI)
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	result, err := cfg.RunQueryForUnsignedResponse(newDefaultQuery())
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestQueryConfig_RunQueryForUnsignedResponse_malformed_two_variables(t *testing.T) {
	cfg := QueryConfig{}
	err := cfg.SetRequestResponseURI("https://coserv/{user}/endpoint/{query}")
	assert.EqualError(t, err, "more than one variable present in endpoint")
}

func TestQueryConfig_RunQueryForUnsignedResponse_ConfigError(t *testing.T) {
	cfg := QueryConfig{}
	_, err := cfg.RunQueryForUnsignedResponse(newDefaultQuery())
	assert.EqualError(t, err, "bad configuration: no request-response URL template")
}

func TestQueryConfig_RunQueryForUnsignedResponse_EncodingError(t *testing.T) {
	cfg := QueryConfig{}
	err := cfg.SetRequestResponseURI("http://example.com/{query}")
	require.NoError(t, err)

	// Invalid query: nil Coserv (or one that fails validation)
	invalidQuery := &coserv.Coserv{}
	_, err = cfg.RunQueryForUnsignedResponse(invalidQuery)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encoding query")
}

func TestQueryConfig_RunQueryForUnsignedResponse_HTTPError(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := QueryConfig{}
	err := cfg.SetRequestResponseURI(testRequestResponseURI)
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	_, err = cfg.RunQueryForUnsignedResponse(newDefaultQuery())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected HTTP response code 404")
}

func TestQueryConfig_RunQueryForUnsignedResponse_DecodeError(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", UnsignedCoSERVMediaType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0xff, 0x00, 0xff, 0x00}) // invalid CBOR
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := QueryConfig{}
	err := cfg.SetRequestResponseURI(testRequestResponseURI)
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	_, err = cfg.RunQueryForUnsignedResponse(newDefaultQuery())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decoding unsigned CoSERV response")
}

func TestQueryConfig_RunQueryForSignedResponse_Success(t *testing.T) {
	signedData, verifier, err := signResponse(newDefaultResponse())
	require.NoError(t, err)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, SignedCoSERVMediaType, r.Header.Get("Accept"))
		w.Header().Set("Content-Type", SignedCoSERVMediaType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(signedData)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := QueryConfig{}
	err = cfg.SetRequestResponseURI(testRequestResponseURI)
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	msg, err := cfg.RunQueryForSignedResponse(newDefaultQuery())
	require.NoError(t, err)
	assert.Equal(t, signedData, msg)

	// Verify signature using the verifier from the signing process
	_, err = ExtractCoservFromSignedResponse(msg, []cose.Verifier{verifier})
	assert.NoError(t, err)
}

func TestQueryConfig_RunQueryForSignedResponse_ConfigError(t *testing.T) {
	cfg := QueryConfig{}
	_, err := cfg.RunQueryForSignedResponse(newDefaultQuery())
	assert.EqualError(t, err, "bad configuration: no request-response URL template")
}

func TestQueryConfig_RunQueryForSignedResponse_EncodingError(t *testing.T) {
	cfg := QueryConfig{}
	err := cfg.SetRequestResponseURI("http://example.com/{query}")
	require.NoError(t, err)
	invalidQuery := &coserv.Coserv{}
	_, err = cfg.RunQueryForSignedResponse(invalidQuery)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encoding query")
}

func TestQueryConfig_RunQueryForSignedResponse_HTTPError(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := QueryConfig{}
	err := cfg.SetRequestResponseURI(testRequestResponseURI)
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	_, err = cfg.RunQueryForSignedResponse(newDefaultQuery())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected HTTP response code 403")
}

func TestQueryConfig_RunQueryForExtractedSignedResponse_Success(t *testing.T) {
	signedData, verifier, err := signResponse(newDefaultResponse())
	require.NoError(t, err)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", SignedCoSERVMediaType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(signedData)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := QueryConfig{}
	err = cfg.SetRequestResponseURI(testRequestResponseURI)
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	result, err := cfg.RunQueryForExtractedSignedResponse(newDefaultQuery(), []cose.Verifier{verifier})
	require.NoError(t, err)
	assert.NotNil(t, result)
}
func TestQueryConfig_RunQueryForExtractedSignedResponse_RunQueryForSignedResponseFails(t *testing.T) {
	cfg := QueryConfig{} // missing URL
	_, err := cfg.RunQueryForExtractedSignedResponse(newDefaultQuery(), nil)
	assert.Error(t, err)
}

func TestExtractCoservFromSignedResponse_Success(t *testing.T) {
	signedData, verifier, err := signResponse(newDefaultResponse())
	require.NoError(t, err)

	result, err := ExtractCoservFromSignedResponse(signedData, []cose.Verifier{verifier})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestExtractCoservFromSignedResponse_NoVerifiers(t *testing.T) {
	signedData, _, err := signResponse(newDefaultResponse())
	require.NoError(t, err)

	_, err = ExtractCoservFromSignedResponse(signedData, []cose.Verifier{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one cose verifier")
}

func TestExtractCoservFromSignedResponse_InvalidCty(t *testing.T) {
	resp := newDefaultResponse()
	payload, err := resp.ToCBOR()
	require.NoError(t, err)

	// Sign with a valid key but a wrong content type
	signer, verifier, err := getSignerAndVerifierFromJWK(testES256KeyJWK)
	require.NoError(t, err)
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmES256
	msg.Headers.Protected[cose.HeaderLabelContentType] = "application/octet-stream" // wrong
	err = msg.Sign(rand.Reader, nil, signer)
	require.NoError(t, err)
	signedData, err := msg.MarshalCBOR()
	require.NoError(t, err)

	_, err = ExtractCoservFromSignedResponse(signedData, []cose.Verifier{verifier})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestExtractCoservFromSignedResponse_MissingCty(t *testing.T) {
	resp := newDefaultResponse()
	payload, err := resp.ToCBOR()
	require.NoError(t, err)

	signer, _, err := getSignerAndVerifierFromJWK(testES256KeyJWK)
	require.NoError(t, err)
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmES256
	// no content type header
	err = msg.Sign(rand.Reader, nil, signer)
	require.NoError(t, err)
	signedData, err := msg.MarshalCBOR()
	require.NoError(t, err)

	_, verifier, err := getSignerAndVerifierFromJWK(testES256KeyJWK)
	require.NoError(t, err)
	_, err = ExtractCoservFromSignedResponse(signedData, []cose.Verifier{verifier})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed with all keys")
}

func TestExtractCoservFromSignedResponse_InvalidCOSE(t *testing.T) {
	var msg cose.Sign1Message
	err := msg.UnmarshalCBOR([]byte("not cbor"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cbor: invalid COSE_Sign1_Tagged object")
}

func TestExtractCoservFromSignedResponse_InvalidPayload(t *testing.T) {
	invalidPayload := []byte{0x01, 0x02, 0x03}
	signer, verifier, err := getSignerAndVerifierFromJWK(testES256KeyJWK)
	require.NoError(t, err)

	msg := cose.NewSign1Message()
	msg.Payload = invalidPayload
	msg.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmES256
	msg.Headers.Protected[cose.HeaderLabelContentType] = UnsignedCoSERVMediaType
	err = msg.Sign(rand.Reader, nil, signer)
	require.NoError(t, err)
	signedData, err := msg.MarshalCBOR()
	require.NoError(t, err)

	_, err = ExtractCoservFromSignedResponse(signedData, []cose.Verifier{verifier})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed with all keys")
}

// Testing cache with 60 seconds Max Age
func TestQueryConfig_WithCache(t *testing.T) {
	var hitCount int32
	respCBOR, err := newDefaultResponse().ToCBOR()
	require.NoError(t, err)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		assert.Equal(t, UnsignedCoSERVMediaType, r.Header.Get("Accept"))
		w.Header().Set("Content-Type", UnsignedCoSERVMediaType)
		w.Header().Set("Cache-Control", "max-age=60")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respCBOR)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := QueryConfig{}
	err = cfg.SetRequestResponseURI(testRequestResponseURI)
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	cfg.EnableCache(true)

	result, err := cfg.RunQueryForUnsignedResponse(newDefaultQuery())
	require.NoError(t, err)
	assert.NotNil(t, result)

	result, err = cfg.RunQueryForUnsignedResponse(newDefaultQuery())
	require.NoError(t, err)
	assert.NotNil(t, result)

	assert.Equal(t, atomic.LoadInt32(&hitCount), int32(1))
}

func TestQueryConfig_WithoutCache(t *testing.T) {
	var hitCount int32
	respCBOR, err := newDefaultResponse().ToCBOR()
	require.NoError(t, err)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		assert.Equal(t, UnsignedCoSERVMediaType, r.Header.Get("Accept"))
		w.Header().Set("Content-Type", UnsignedCoSERVMediaType)
		w.Header().Set("Cache-Control", "max-age=60")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respCBOR)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	cfg := QueryConfig{}
	err = cfg.SetRequestResponseURI(testRequestResponseURI)
	require.NoError(t, err)
	err = cfg.SetClient(client)
	require.NoError(t, err)

	cfg.EnableCache(false)

	result, err := cfg.RunQueryForUnsignedResponse(newDefaultQuery())
	require.NoError(t, err)
	assert.NotNil(t, result)

	result, err = cfg.RunQueryForUnsignedResponse(newDefaultQuery())
	require.NoError(t, err)
	assert.NotNil(t, result)

	assert.Equal(t, atomic.LoadInt32(&hitCount), int32(2))
}
