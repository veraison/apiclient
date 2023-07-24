package management

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/apiclient/common"
)

var (
	testEndpointURI = &url.URL{
		Scheme: "http",
		Host:   "veraison.example",
		Path:   "/management/v1",
	}

	testPolicy = &Policy{
		Type:  "opa",
		UUID:  uuid.New(),
		Rules: "test rule",
		Name:  "test_name",
	}
)

func TestService_NewService(t *testing.T) {
	_, err := NewService(string([]byte{0x7f}))
	assert.EqualError(t, err, "malformed URI: parse \"\\x7f\": net/url: invalid control character in URL")

	_, err = NewService("test")
	assert.EqualError(t, err, "URI is not absolute: \"test\"")

	service, err := NewService("http://veraison.example:9999/test/v1")
	assert.NoError(t, err)
	assert.Equal(t, "veraison.example:9999", service.EndPointURI.Host)
}

func TestService_CreateOPAPolicy(t *testing.T) {
	expectedURI := testEndpointURI.JoinPath("policy", "test_scheme")
	expectedURI.RawQuery = "name=test_name"

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, OPARulesMediaType, r.Header.Get("Content-Type"))
		assert.Equal(t, PolicyMediaType, r.Header.Get("Accept"))
		assert.Equal(t, expectedURI.RequestURI(), r.RequestURI)

		w.Header().Add("Content-Type", PolicyMediaType)
		w.WriteHeader(http.StatusCreated)
		_, err := w.Write(toBytes(testPolicy))
		assert.NoError(t, err)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	service := Service{
		EndPointURI: testEndpointURI,
		Client:      client,
	}

	pol, err := service.CreateOPAPolicy("test_scheme", []byte{}, "test_name")
	require.NoError(t, err)
	assert.Equal(t, pol.Name, testPolicy.Name)
	assert.Equal(t, pol.UUID, testPolicy.UUID)
}

func TestService_ActivatePolicy(t *testing.T) {
	id := uuid.New()

	expectedURI := testEndpointURI.JoinPath("policy", "test_scheme", id.String(), "activate")

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, expectedURI.RequestURI(), r.RequestURI)

		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte{})
		assert.NoError(t, err)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	service := Service{
		EndPointURI: testEndpointURI,
		Client:      client,
	}

	err := service.ActivatePolicy("test_scheme", id)
	require.NoError(t, err)
}

func TestService_DeactivateAllPolicies(t *testing.T) {
	expectedURI := testEndpointURI.JoinPath("policies", "test_scheme", "deactivate")

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, expectedURI.RequestURI(), r.RequestURI)

		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte{})
		assert.NoError(t, err)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	service := Service{
		EndPointURI: testEndpointURI,
		Client:      client,
	}

	err := service.DeactivateAllPolicies("test_scheme")
	require.NoError(t, err)
}

func TestService_GetActivePolicy(t *testing.T) {
	expectedURI := testEndpointURI.JoinPath("policy", "test_scheme")

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, PolicyMediaType, r.Header.Get("Accept"))
		assert.Equal(t, expectedURI.RequestURI(), r.RequestURI)

		w.Header().Add("Content-Type", PolicyMediaType)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(toBytes(testPolicy))
		assert.NoError(t, err)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	service := Service{
		EndPointURI: testEndpointURI,
		Client:      client,
	}

	pol, err := service.GetActivePolicy("test_scheme")
	require.NoError(t, err)
	assert.Equal(t, pol.Name, testPolicy.Name)
	assert.Equal(t, pol.UUID, testPolicy.UUID)
}

func TestService_GetPolicy(t *testing.T) {
	expectedURI := testEndpointURI.JoinPath("policy", "test_scheme", testPolicy.UUID.String())

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, PolicyMediaType, r.Header.Get("Accept"))
		assert.Equal(t, expectedURI.RequestURI(), r.RequestURI)

		w.Header().Add("Content-Type", PolicyMediaType)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(toBytes(testPolicy))
		assert.NoError(t, err)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	service := Service{
		EndPointURI: testEndpointURI,
		Client:      client,
	}

	pol, err := service.GetPolicy("test_scheme", testPolicy.UUID)
	require.NoError(t, err)
	assert.Equal(t, pol.Name, testPolicy.Name)
	assert.Equal(t, pol.UUID, testPolicy.UUID)
}

func TestService_GetPolicies(t *testing.T) {
	expectedURI := testEndpointURI.JoinPath("policies", "test_scheme")
	expectedURI.RawQuery = "name=test_name"

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, PoliciesMediaType, r.Header.Get("Accept"))
		assert.Equal(t, expectedURI.RequestURI(), r.RequestURI)

		w.Header().Add("Content-Type", PoliciesMediaType)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(toBytes([]*Policy{testPolicy}))
		assert.NoError(t, err)
	})

	client, teardown := common.NewTestingHTTPClient(h)
	defer teardown()

	service := Service{
		EndPointURI: testEndpointURI,
		Client:      client,
	}

	pols, err := service.GetPolicies("test_scheme", "test_name")
	require.NoError(t, err)
	assert.Len(t, pols, 1)
	assert.Equal(t, pols[0].Name, testPolicy.Name)
	assert.Equal(t, pols[0].UUID, testPolicy.UUID)
}

func toBytes(in interface{}) []byte {
	b, err := json.Marshal(in)
	if err != nil {
		panic(err)
	}
	return b
}
