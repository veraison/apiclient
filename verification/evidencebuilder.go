// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package verification

// EvidenceBuilder is the interface between the challenge-response protocol FSM
// and the user. The user is given a nonce and the list of acceptable Evidence
// formats and is asked to return the serialized Evidence as a byte array
// together with its media type - or an error if anything goes wrong.
type EvidenceBuilder interface {
	BuildEvidence(nonce []byte, accept []string) (evidence []byte, mediaType string, err error)
}
