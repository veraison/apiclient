// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package apiclient

import "errors"

// ChallengeResponseCallback is the interface between the challenge-response
// protocol FSM and the user. The user is given a nonce and the list of
// acceptable Evidence formats; the user returns the serialized Evidence as a
// byte array together with its media type - or an error if anything goes wrong.
type ChallengeResponseCallback func(nonce []byte, accept []string) (evidence []byte, mediaType string, err error)

// ChallengeResponseConfig holds the configuration for one or more
// challenge-response exchanges
type ChallengeResponseConfig struct {
	Nonce         []byte                    // an explicit nonce supplied by the user
	NonceSz       uint                      // the size of a nonce to be provided by server
	Callback      ChallengeResponseCallback // Evidence generation logics supplied by the user
	NewSessionURI string                    // URI of the "/newSession" endpoint
}

// Run implements the challenge-response protocol FSM invoking the user callback.
func (cfg ChallengeResponseConfig) Run() error {
	return errors.New("TODO")
}
