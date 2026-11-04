// Copyright 2021-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package provisioning

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/veraison/apiclient/auth"
	"github.com/veraison/apiclient/common"
)

const (
	HTTPS = "https"
)

// CommonConfig holds the context of an endorsement submission/activate/deactivate session
type CommonConfig struct {
	// paths to CA certs to be used in addition to system certs for TLS connections
	caCerts []string
	// HTTP(s) client connection configuration
	client *common.Client
	// when set, auth supplies the Authorization header for requests
	auth auth.IAuthenticator
	// use TLS for server connections
	useTLS bool
	// allow insecure server connections (only matters when useTLS is true)
	isInsecure bool
	// URI of the /activate, /deactivate or /submit endpoint
	URI string
}

// SetClient sets the HTTP(s) client connection configuration
func (cfg *CommonConfig) SetClient(client *common.Client) error {
	if client == nil {
		return errors.New("no client supplied")
	}

	c := *client
	if cfg.auth != nil {
		c.Auth = cfg.auth
	}

	cfg.client = &c
	return nil
}

// SetAuth sets the IAuthenticator that will be used
func (cfg *CommonConfig) SetAuth(a auth.IAuthenticator) {
	cfg.auth = a
	if cfg.client != nil {
		cfg.client.Auth = cfg.auth
	}
}

// SetIsInsecure sets the isInsecure parameter using the supplied val
func (cfg *CommonConfig) SetIsInsecure(val bool) {
	cfg.isInsecure = val
}

// SetCerts sets the caCerts parameter to the specified paths
func (cfg *CommonConfig) SetCerts(paths []string) {
	cfg.caCerts = paths
}

// SetURI sets the URI Parameter
func (cfg *CommonConfig) SetURI(uri string) error {
	scheme, err := checkURI(uri)
	if err != nil {
		return err
	}

	cfg.useTLS = scheme == HTTPS
	cfg.URI = uri
	return nil
}

func (cfg *CommonConfig) initClient() error {
	if cfg.client != nil {
		return nil // client already initialized
	}

	if !cfg.useTLS {
		cfg.client = common.NewClient(cfg.auth)
		return nil
	}

	if cfg.isInsecure {
		cfg.client = common.NewInsecureTLSClient(cfg.auth)
		return nil
	}

	var err error

	cfg.client, err = common.NewTLSClient(cfg.auth, cfg.caCerts)

	return err
}

// checkURI parses/checks the URI and returns the http scheme
func checkURI(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("malformed URI: %w", err)
	}
	if !u.IsAbs() {
		return "", errors.New("uri is not absolute")
	}

	if u.Scheme != "http" && u.Scheme != HTTPS {
		return "", fmt.Errorf("unknown scheme: %s, only http and https are supported", u.Scheme)
	}

	return u.Scheme, nil
}
