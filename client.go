// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"net/http"
	"time"
)

// Client holds configuration data associated with the HTTP(s) session
type Client struct {
	HTTPClient http.Client
	// TODO(tho) API tokens and client credentials
}

// NewClient instantiates a new Client
func NewClient() *Client {
	return &Client{
		HTTPClient: http.Client{
			Timeout: 5 * time.Second,
		},
	}
}
