// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package auth

import "fmt"

// Method is the enumeration of authentication methods supported by Veraison
// service. It implements the pflag.Value interface.
type Method string

const (
	MethodPassthrough Method = "passthrough"
	MethodBasic       Method = "basic"
	MethodOauth2      Method = "oauth2"
)

// String representation of the Method
func (o *Method) String() string {
	return string(*o)
}

// Set the value of the Method
func (o *Method) Set(v string) error {
	switch v {
	case "none", "passthrough":
		*o = MethodPassthrough
	case "basic":
		*o = MethodBasic
	case "oauth2":
		*o = MethodOauth2
	default:
		return fmt.Errorf("unexpected Method %q", v)
	}

	return nil
}

// Type returns the string representing the type name (used by pflag).
func (o *Method) Type() string {
	return "Method"
}
