// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package verification

import "fmt"

// EvidenceBuilder is the interface between the challenge-response protocol FSM
// and the user. The user is given a nonce and the list of acceptable Evidence
// formats and is asked to return the serialized Evidence as a byte array
// together with its media type - or an error if anything goes wrong.
type EvidenceBuilder interface {
	BuildEvidence(nonce []byte, accept []string) (evidence []byte, mediaType string, err error)
}

// StaticEvidenceBuilder is a simple EvidenceBuilder that always returns the
// same static evidence and media type.
// This is can be used when the evidence is already available and does not
// need to be dynamically generated (RP mode) or for testing purposes.
type StaticEvidenceBuilder struct {
	evidence  []byte
	mediaType string
}

// BuildEvidence returns the static evidence if the media type is in the list of
// accepted media types; otherwise, it returns an error.
// Note that the nonce parameter is ignored.
func (s StaticEvidenceBuilder) BuildEvidence(_ []byte, accept []string) ([]byte, string, error) { // nolint: gocritic
	for _, ct := range accept {
		if ct == s.mediaType {
			return s.evidence, s.mediaType, nil
		}
	}
	return nil, "", fmt.Errorf("no match for %s on accepted media types %v", s.mediaType, accept)
}

// NewStaticEvidenceBuilder creates a new StaticEvidenceBuilder with the
// specified evidence and media type.
func NewStaticEvidenceBuilder(evidence []byte, mediaType string) EvidenceBuilder {
	return &StaticEvidenceBuilder{
		evidence:  evidence,
		mediaType: mediaType,
	}
}
