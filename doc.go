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
		UserCallback:  MyChallengeResponseCallback,
		NewSessionURI: "http://veraison.example/challenge-response/v1/newSession",
	}

or just the size of a nonce to be provided by the server side:

	cfg := ChallengeResponseConfig{
		NonceSz:        32,
		UserCallback:   MyChallengeResponseCallback,
		NewSessionURI: "http://veraison.example/challenge-response/v1/newSession",
	}

The user can also supply a custom Client object, for example to appropriately
configure the underlying TLS transport:

    cfg.Client = &Client{
		HTTPClient: http.Client{
			Transport: myTLSConfig,
		}
	}

The user can also request to explicitly delete the session resource at the
server instead of letting it expire:

    cfg.DeleteSession = true

Then the Run method is invoked on the instantiated ChallengeReponseConfig
object to trigger the protocol FSM, hiding any details about the synchronus /
async nature of the underlying exchange:

	attestationResult, err := cfg.Run()

On success, the Attestation Result, is returned as a JSON string:

	if err == nil {
		fmt.Println("%s", string(attestationResult))
	}

*/
package apiclient
