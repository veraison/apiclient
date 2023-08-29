// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/mitchellh/mapstructure"
)

type BasicAuthenticator struct {
	Username string
	Password string
}

func (o *BasicAuthenticator) Configure(cfg map[string]interface{}) error {
	decoded := struct {
		Username string                 `mapstructure:"username"`
		Password string                 `mapstructure:"password"`
		Rest     map[string]interface{} `mapstructure:",remain"`
	}{}

	if err := mapstructure.Decode(cfg, &decoded); err != nil {
		return err
	}

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

func (o *BasicAuthenticator) EncodeHeader() (string, error) {
	if err := o.validate(); err != nil {
		return "", err
	}

	credsRaw := fmt.Sprintf("%s:%s", o.Username, o.Password)
	credsEncoded := base64.StdEncoding.EncodeToString([]byte(credsRaw))
	header := fmt.Sprintf("Basic %s", credsEncoded)

	return header, nil
}

func (o *BasicAuthenticator) validate() error {
	if o.Username == "" {
		return errors.New("missing username")
	}

	if o.Password == "" {
		return errors.New("missing password")
	}

	return nil
}
