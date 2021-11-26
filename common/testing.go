// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
)

// NewTestingHTTPClient creates an HTTP test server (with a configurable request
// handler), an API Client and connects them together.  The API client and the
// server's shutdown switch are returned.
func NewTestingHTTPClient(handler http.Handler) (cli *Client, closerFn func()) {
	srv := httptest.NewServer(handler)

	cli = &Client{
		HTTPClient: http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
					return net.Dial(network, srv.Listener.Addr().String())
				},
			},
		},
	}

	closerFn = srv.Close

	return
}
