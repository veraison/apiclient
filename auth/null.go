// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package auth

type NullAuthenticator struct{}

func (o *NullAuthenticator) Configure(cfg map[string]interface{}) error {
	return nil
}

func (o *NullAuthenticator) EncodeHeader() (string, error) {
	return "", nil
}
