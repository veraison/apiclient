// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// NewTLSTransport returns a pointer to a new http.Transport with TLS config
// initilaized with system certs as well as specified certPaths.
func NewTLSTransport(certPaths []string) (*http.Transport, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	for _, certPath := range certPaths {
		rawCert, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("could not read cert: %w", err)
		}

		if ok := certPool.AppendCertsFromPEM(rawCert); !ok {
			return nil, fmt.Errorf("invalid cert in %s", certPath)
		}
	}

	return &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    certPool,
			MinVersion: tls.VersionTLS12,
		},
	}, nil
}
