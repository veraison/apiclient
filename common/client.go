// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/veraison/apiclient/auth"
)

// Client holds configuration data associated with the HTTP(s) session, and a
// reference to an IAuthenticator that is used to provide Authorization headers
// for requests.
type Client struct {
	HTTPClient http.Client
	Auth       auth.IAuthenticator
}

// NewClient instantiates a new Client with a fixed 5s timeout. The client will
// use the provided IAuthenticator for requests, if it is not nil
func NewClient(a auth.IAuthenticator) *Client {
	return &Client{
		HTTPClient: http.Client{
			Timeout: 5 * time.Second,
		},
		Auth: a,
	}
}

func (c Client) DeleteResource(uri string) error {
	req, err := c.newRequest("DELETE", uri, http.NoBody)
	if err != nil {
		return fmt.Errorf("DELETE %q, request creation failed: %w", uri, err)
	}

	res, err := c.send(req)
	if err != nil {
		return err
	}

	// Acceptable response codes are 200, 202 and 204
	switch res.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusNoContent:
		return nil
	default:
		return fmt.Errorf("DELETE %q, response has unexpected status: %s", uri, res.Status)
	}
}

func (c Client) PostResource(body []byte, ct, accept, uri string) (*http.Response, error) {
	req, err := c.newRequest("POST", uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("POST %q, request creation failed: %w", uri, err)
	}

	req.Header.Set("Content-Type", ct)
	req.Header.Set("Accept", accept)

	return c.send(req)
}

func (c Client) PostEmptyResource(accept, uri string) (*http.Response, error) {
	req, err := c.newRequest("POST", uri, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("POST %q, request creation failed: %w", uri, err)
	}

	req.Header.Set("Accept", accept)

	return c.send(req)
}

func (c Client) GetResource(accept, uri string) (*http.Response, error) {
	req, err := c.newRequest("GET", uri, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("POST %q, request creation failed: %w", uri, err)
	}

	req.Header.Set("Accept", accept)

	return c.send(req)
}

func (c Client) newRequest(method, uri string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, uri, body)
	if err != nil {
		return nil, err
	}

	if c.Auth != nil {
		header, err := c.Auth.EncodeHeader()
		if err != nil {
			return nil, fmt.Errorf("could not get Authorization header: %w", err)
		}
		if header != "" {
			req.Header.Set("Authorization", header)
		}
	}

	return req, nil
}

func (c Client) send(req *http.Request) (*http.Response, error) {
	hc := &c.HTTPClient

	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}

	return res, nil
}
