// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"bytes"
	"fmt"
	"net/http"
	"time"
)

// Client holds configuration data associated with the HTTP(s) session
type Client struct {
	HTTPClient http.Client
}

// NewClient instantiates a new Client with a fixed 5s timeout
func NewClient() *Client {
	return &Client{
		HTTPClient: http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (c Client) DeleteResource(uri string) error {
	req, err := http.NewRequest("DELETE", uri, http.NoBody)
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
	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("POST %q, request creation failed: %w", uri, err)
	}

	req.Header.Set("Content-Type", ct)
	req.Header.Set("Accept", accept)

	return c.send(req)
}

func (c Client) PostEmptyResource(accept, uri string) (*http.Response, error) {
	req, err := http.NewRequest("POST", uri, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("POST %q, request creation failed: %w", uri, err)
	}

	req.Header.Set("Accept", accept)

	return c.send(req)
}

func (c Client) GetResource(accept, uri string) (*http.Response, error) {
	req, err := http.NewRequest("GET", uri, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("POST %q, request creation failed: %w", uri, err)
	}

	req.Header.Set("Accept", accept)

	return c.send(req)
}

func (c Client) send(req *http.Request) (*http.Response, error) {
	hc := &c.HTTPClient

	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}

	return res, nil
}
