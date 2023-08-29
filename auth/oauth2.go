// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"golang.org/x/oauth2"
)

type Oauth2Authenticator struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Username     string
	Password     string

	Token *oauth2.Token
}

func (o *Oauth2Authenticator) Configure(cfg map[string]interface{}) error {
	decoded := struct {
		TokenURL     string                 `mapstructure:"token_url" valid:"url"`
		ClientID     string                 `mapstructure:"client_id"`
		ClientSecret string                 `mapstructure:"client_secret"`
		Username     string                 `mapstructure:"username"`
		Password     string                 `mapstructure:"password"`
		Rest         map[string]interface{} `mapstructure:",remain"`
	}{}

	if err := mapstructure.Decode(cfg, &decoded); err != nil {
		return err
	}

	o.ClientID = decoded.ClientID
	o.ClientSecret = decoded.ClientSecret
	o.TokenURL = decoded.TokenURL
	o.Username = decoded.Username
	o.Password = decoded.Password

	if err := o.validate(); err != nil {
		return err
	}

	if len(decoded.Rest) > 0 {
		var unexpected []string
		for k := range decoded.Rest {
			unexpected = append(unexpected, k)
		}
		return fmt.Errorf("unexpected fields in config: %s",
			strings.Join(unexpected, ", "))
	}

	return nil
}

func (o *Oauth2Authenticator) EncodeHeader() (string, error) {
	var err error

	if o.Token == nil || o.Token.Expiry.Before(time.Now()) {
		o.Token, err = o.obtainToken()
		if err != nil {
			return "", err
		}
	}

	header := fmt.Sprintf("Bearer %s", o.Token.AccessToken)

	return header, nil
}

func (o *Oauth2Authenticator) obtainToken() (*oauth2.Token, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}

	ctx := context.Background()
	conf := &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Scopes:       []string{"openid"},
		Endpoint: oauth2.Endpoint{
			TokenURL: o.TokenURL,
		},
	}

	return conf.PasswordCredentialsToken(ctx, o.Username, o.Password)
}

func (o *Oauth2Authenticator) validate() error {
	if o.ClientID == "" {
		return errors.New("missing client_id")
	}

	if o.ClientSecret == "" {
		return errors.New("missing client_secret")
	}

	if o.TokenURL == "" {
		return errors.New("missing token_url")
	}

	if _, err := url.Parse(o.TokenURL); err != nil {
		return fmt.Errorf("invalid token_url: %w", err)
	}

	if o.Username == "" {
		return errors.New("missing username")
	}

	if o.Password == "" {
		return errors.New("missing password")
	}

	return nil
}
