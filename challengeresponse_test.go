// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func MyChallengeResponseCallback(nonce []byte, accept []string) ([]byte, string, error) {
	return []byte{0x0e, 0x0d, 0x0c}, "application/my-evidence-media-type", nil
}

func TestChallengeResponseConfig_Run(t *testing.T) {
	cfg := ChallengeResponseConfig{
		Nonce:         []byte{0xde, 0xad, 0xbe, 0xef},
		Callback:      MyChallengeResponseCallback,
		NewSessionURI: "https://veraison.example/challenge-response/v1/newSession",
	}

	assert.Error(t, cfg.Run(), "TODO")
}
