// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package management

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/veraison/apiclient/common"
)

const (
	OPARulesMediaType  = "application/vnd.veraison.policy.opa"
	PolicyMediaType    = "application/vnd.veraison.policy+json"
	PoliciesMediaType  = "application/vnd.veraison.policies+json"
	WellKnownMediaType = "application/vnd.veraison.discovery+json"

	WellKnownPath = "/.well-known/veraison/management"
)

// Service is the primary interface to the management service API.
type Service struct {
	// Client is the underlying client used for HTTP requests.
	Client *common.Client

	// EndPointURI is the top-level service API URL. Individual operations
	// endpoints are relative to this.
	EndPointURI *url.URL
}

// NewService creates a new Service instance using the provided endpoint
// URI and the default HTTP client.
func NewService(uri string) (*Service, error) {
	m := Service{Client: common.NewClient()}

	if err := m.SetEndpointURI(uri); err != nil {
		return nil, err
	}

	return &m, nil
}

// SetClient sets the HTTP(s) client connection configuration
func (o *Service) SetClient(client *common.Client) error {
	if client == nil {
		return errors.New("no client supplied")
	}
	o.Client = client
	return nil
}

// SetEndpointURI sets the URI if the Veraison services management endpoint.
func (o *Service) SetEndpointURI(uri string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("malformed URI: %w", err)
	}

	if !u.IsAbs() {
		return fmt.Errorf("URI is not absolute: %q", uri)
	}

	o.EndPointURI = u

	return nil
}

// CreateOPAPolicy is a wrapper around CreatePolicy that assumes the OPA media
// type.
func (o *Service) CreateOPAPolicy(scheme string, rules []byte, name string) (*Policy, error) {
	return o.CreatePolicy(scheme, OPARulesMediaType, rules, name)
}

// CreatePolicy creates a new policy associated with the specified scheme based
// on the specified content type and rules, with the specified name.
func (o *Service) CreatePolicy(
	scheme string,
	ct string,
	rules []byte,
	name string,
) (*Policy, error) {
	postURI := o.EndPointURI.JoinPath("policy", scheme)

	qvals := url.Values{}
	if name != "" {
		qvals.Add("name", name)
	}
	postURI.RawQuery = qvals.Encode()

	res, err := o.Client.PostResource(rules, ct, PolicyMediaType, postURI.String())
	if err != nil {
		return nil, fmt.Errorf("post request failed: %w", err)
	}

	if err := common.CheckResponse(res, http.StatusCreated); err != nil {
		return nil, err
	}

	return policyFromResponse(res)
}

// ActivatePolicy activates a previously created policy with the policyID UUID,
// associated with the specified scheme. This deactivates any previously-active
// policy.
func (o *Service) ActivatePolicy(scheme string, policyID uuid.UUID) error {
	postURI := o.EndPointURI.JoinPath("policy", scheme, policyID.String(), "activate")

	res, err := o.Client.PostEmptyResource(PolicyMediaType, postURI.String())
	if err != nil {
		return fmt.Errorf("post request failed: %w", err)
	}

	if err := common.CheckResponse(res, http.StatusOK); err != nil {
		return err
	}

	return nil
}

// DeactivateAllPolicies deactivates all policies associated with the specified
// scheme.
func (o *Service) DeactivateAllPolicies(scheme string) error {
	postURI := o.EndPointURI.JoinPath("policies", scheme, "deactivate")

	res, err := o.Client.PostEmptyResource(PolicyMediaType, postURI.String())
	if err != nil {
		return fmt.Errorf("post request failed: %w", err)
	}

	if err := common.CheckResponse(res, http.StatusOK); err != nil {
		return err
	}

	return nil
}

// GetActivePolicy returns the currently active policy for the specified
// scheme. If no such policy exists, an error is returned.
func (o *Service) GetActivePolicy(scheme string) (*Policy, error) {
	getURI := o.EndPointURI.JoinPath("policy", scheme)

	res, err := o.Client.GetResource(PolicyMediaType, getURI.String())
	if err != nil {
		return nil, fmt.Errorf("get request failed: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP response code %d", res.StatusCode)
	}

	return policyFromResponse(res)
}

// GetPolicy returns the policy with the specified UUID associated with the
// specified scheme.
func (o *Service) GetPolicy(scheme string, policyID uuid.UUID) (*Policy, error) {
	getURI := o.EndPointURI.JoinPath("policy", scheme, policyID.String())

	res, err := o.Client.GetResource(PolicyMediaType, getURI.String())
	if err != nil {
		return nil, fmt.Errorf("get request failed: %w", err)
	}

	if err := common.CheckResponse(res, http.StatusOK); err != nil {
		return nil, err
	}

	return policyFromResponse(res)
}

// GetPolicies returns all policies associated with the specified scheme. If
// the name is specified as something other than "", only policies with that
// name are returned.
func (o *Service) GetPolicies(scheme string, name string) ([]*Policy, error) {
	getURI := o.EndPointURI.JoinPath("policies", scheme)

	qvals := url.Values{}
	if name != "" {
		qvals.Add("name", name)
	}
	getURI.RawQuery = qvals.Encode()

	res, err := o.Client.GetResource(PoliciesMediaType, getURI.String())
	if err != nil {
		return nil, fmt.Errorf("get request failed: %w", err)
	}

	if err := common.CheckResponse(res, http.StatusOK); err != nil {
		return nil, err
	}

	return policiesFromResponse(res)
}

// GetSupportedSchemes returns a []string with the names of schemes supported
// by the service.
func (o *Service) GetSupportedSchemes() ([]string, error) {
	wellKnownURI := &url.URL{
		Scheme: o.EndPointURI.Scheme,
		Host:   o.EndPointURI.Host,
		Path:   WellKnownPath,
	}

	res, err := o.Client.GetResource(WellKnownMediaType, wellKnownURI.String())
	if err != nil {
		return nil, fmt.Errorf("get request failed: %w", err)
	}

	if err := common.CheckResponse(res, http.StatusOK); err != nil {
		return nil, err
	}

	var schemesInfo struct {
		Schemes []string `json:"attestation-schemes"`
	}

	if err := common.DecodeJSONBody(res, &schemesInfo); err != nil {
		return nil, fmt.Errorf(
			"could not decode well-known info response (status %d): %w",
			res.StatusCode,
			err,
		)
	}

	return schemesInfo.Schemes, nil

}

func policyFromResponse(res *http.Response) (*Policy, error) {
	if res.ContentLength == 0 {
		return nil, errors.New("empty body")
	}

	ct := res.Header.Get("Content-Type")
	if ct != PolicyMediaType {
		return nil, fmt.Errorf(
			"policy response with unexpected content type: %q", ct,
		)
	}

	var policy Policy

	if err := common.DecodeJSONBody(res, &policy); err != nil {
		return nil, fmt.Errorf("failure decoding policy: %w", err)
	}

	return &policy, nil
}

func policiesFromResponse(res *http.Response) ([]*Policy, error) {
	if res.ContentLength == 0 {
		return nil, errors.New("empty body")
	}

	ct := res.Header.Get("Content-Type")
	if ct != PoliciesMediaType {
		return nil, fmt.Errorf(
			"policies response with unexpected content type: %q", ct,
		)
	}

	var policies []*Policy

	if err := common.DecodeJSONBody(res, &policies); err != nil {
		return nil, fmt.Errorf("failure decoding policies: %w", err)
	}

	return policies, nil
}
