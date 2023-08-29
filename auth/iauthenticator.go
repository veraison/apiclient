// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package auth

type IAuthenticator interface {
	Configure(cfg map[string]interface{}) error
	EncodeHeader() (string, error)
}
