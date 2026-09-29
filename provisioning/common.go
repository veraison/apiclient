// Copyright 2021-26 Contributors to the Veraison project.
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
	CACerts    []string            // paths to CA certs to be used in addition to system certs for TLS connections
	Client     *common.Client      // HTTP(s) client connection configuration
	Auth       auth.IAuthenticator // when set, Auth supplies the Authorization header for requests
	UseTLS     bool                // use TLS for server connections
	IsInsecure bool                // allow insecure server connections (only matters when UseTLS is true)
}

// SetClient sets the HTTP(s) client connection configuration
func (cfg *CommonConfig) SetClient(client *common.Client) error {
	if client == nil {
		return errors.New("no client supplied")
	}

	if cfg.Auth != nil {
		client.Auth = cfg.Auth
	}

	cfg.Client = client
	return nil
}

// SetAuth sets the IAuthenticator that will be used
func (cfg *CommonConfig) SetAuth(a auth.IAuthenticator) {
	cfg.Auth = a
	if cfg.Client != nil {
		cfg.Client.Auth = cfg.Auth
	}
}

// SetIsInsecure sets the IsInsecure parameter using the supplied val
func (cfg *CommonConfig) SetIsInsecure(val bool) {
	cfg.IsInsecure = val
}

// SetCerts sets the CACerts parameter to the specified paths
func (cfg *CommonConfig) SetCerts(paths []string) {
	cfg.CACerts = paths
}

func (cfg *CommonConfig) initClient() error {
	if cfg.Client != nil {
		return nil // client already initialized
	}

	if !cfg.UseTLS {
		cfg.Client = common.NewClient(cfg.Auth)
		return nil
	}

	if cfg.IsInsecure {
		cfg.Client = common.NewInsecureTLSClient(cfg.Auth)
		return nil
	}

	var err error

	cfg.Client, err = common.NewTLSClient(cfg.Auth, cfg.CACerts)

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
