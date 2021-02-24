// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

/*
Package apiclient implements the interaction model described in
https://github.com/veraison/veraison/tree/main/docs/api

Challenge-Response

The user provides the Evidence generation logics by implementing a
ChallengeResponseCallback function:

	func MyChallengeResponseCallback(nonce []byte, accept []string) ([]byte, string, error) {
		for ct := range accept {
			if ct == "application/my-evidence-media-type" {
				evidence, err := myEvidenceBuilder(nonce)
				if err != nil { ... }

				return evidence, ct, nil
			}
		}

		return nil, "", errors.New("no match on accepted media types")
	}


The user then creates a ChallengeResponseConfig object supplying the callback
and either an explicit nonce:

	cfg := ChallengeResponseConfig{
		Nonce:         []byte{0xde, 0xad, 0xbe, 0xef},
		Callback:       MyChallengeResponseCallback,
		NewSessionURI: "https://veraison.example/challenge-response/v1/newSession",
	}

or just the size of a nonce to be provided by the server side:

	cfg := ChallengeResponseConfig{
		NonceSz:        32,
		Callback:       MyChallengeResponseCallback,
		NewSessionURI: "https://veraison.example/challenge-response/v1/newSession",
	}

Then the Run method is invoked on the instantiated ChallengeReponseConfig
object to trigger the protocol FSM, hiding any details about the synchronus /
async nature of the underlying exchange:

	attestationResult, mediaType, err := cfg.Run()
	if err == nil {
		fmt.Println("success!")
	}

On success, the Attestation Result, together with its media type, is returned.
*/
package apiclient
