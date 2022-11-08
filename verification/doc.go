// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

/*
Package apiclient/verification implements the interaction model described in
https://github.com/veraison/veraison/tree/main/docs/api/challenge-response

Challenge-Response, atomic operation

Using this mode of operation the whole API client exchange is handled
atomically through a single invocation of the Run() method.

The user provides the Evidence generation logics by implementing the
EvidenceBuilder interface:

	type MyEvidenceBuilder struct {
		// build context (e.g., signing key material, claims template, etc.)
	}

	func (eb MyEvidenceBuilder) BuildEvidence(nonce []byte, accept []string) ([]byte, string, error) {
		for _, ct := range accept {
			if ct == "application/my-evidence-media-type" {
				evidence, err := buildEvidence(nonce, eb)
				if err != nil { ... }

				return evidence, ct, nil
			}
		}

		return nil, "", errors.New("no match on accepted media types")
	}


The user then creates a ChallengeResponseConfig object supplying the callback
and either an explicit nonce:

	cfg := ChallengeResponseConfig{
		Nonce:           []byte{0xde, 0xad, 0xbe, 0xef},
		EvidenceBuilder: MyEvidenceBuilder{...},
		NewSessionURI:   "http://veraison.example/challenge-response/v1/newSession",
	}

or just the size of a nonce to be provided by the server side:

	cfg := ChallengeResponseConfig{
		NonceSz:         32,
		EvidenceBuilder: MyEvidenceBuilder{...},
		NewSessionURI:   "http://veraison.example/challenge-response/v1/newSession",
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
		fmt.Println(string(attestationResult))
	}

Challenge-Response, split operation

Using this mode of operation the client is responsible for dealing with each
API call separately, invoking the right API method at the right time and place.

In this mode, users does not provide the Evidence generation logics through
the EvidenceBuilder interface. Instead, they will need to plug in their
Evidence building logics between the call to NewSession() and the subsequent
ChallengeResponse().

Similarly to the atomic operation case, users create a
ChallengeResponseConfig object supplying either an explicit nonce or the
requested nonce size, and any other applicable configuration parameter, e.g., a
custom Client:

	cfg := ChallengeResponseConfig{
		Nonce:         []byte{0xde, 0xad, 0xbe, 0xef},
		NewSessionURI: "http://veraison.example/challenge-response/v1/newSession",
		Client: &Client{
			HTTPClient: http.Client{
				Transport: myTLSConfig,
			},
		},
	}

Same as the atomic model, users can also request to explicitly delete the
session resource on the server instead of letting it expire by setting the
DeleteSession configuration parameter to true.

The NewSession() method is then invoked on the instantiated
ChallengeReponseConfig object to trigger the creation of a new session
resource on the server:

	newSessionCtx, sessionURI, err := cfg.NewSession()

Users need to use the nonce returned in newSessionCtx.Nonce to trigger a
challenge-response session with the Attester and obtain the Evidence. Users
will typically make use of the acceptable Evidence formats advertised by the
server in newSessionCtx.Accept as an additional input to the protocol with
the Attester.

When the Evidence has been obtained, the ChallengeResponse() method can be
invoked to submit it to the allocated session with the Verifier that, on
success, will return the Attestation Result:

	attestationResult, err := cfg.ChallengeResponse(evidence, mediaType, sessionURI)
*/
package verification
