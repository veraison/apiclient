// Copyright 2021-26 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

/*
Package apiclient/provisioning implements the interaction model described in
https://github.com/veraison/veraison/tree/main/docs/api/endorsement-provisioning

# Submit

The whole API client exchange is handled via a single invocation of the Run()
method.

The user creates a SubmitConfig object supplying the URL of the /submit
endpoint:

	cfg := SubmitConfig{
		SubmitURI:	"http://veraison.example/endorsement-provisioning/v1/submit",
	}

The user can also supply a custom Client object, for example to appropriately
configure the underlying TLS transport:

	client := &Client{
		HTTPClient: http.Client{
			Transport: myTLSConfig,
		}
	}
	cfg.SetClient(client)

The user can also request to explicitly delete the session resource at the
server instead of letting it expire:

	cfg.DeleteSession = true

Then the Run method is invoked on the instantiated SubmitConfig object to
trigger the protocol FSM, hiding any details about the synchronus / async nature
of the underlying exchange.  The user must supply the byte buffer containing the
serialized endorsement, and the associated media type:

	err := cfg.Run(corimBuf, "application/corim+cbor")

On success err is nil.

# Activate/Deactivate (Endorsement Lifecycle Management (ELM) Interface)

The user creates a ActivateConfig object supplying the URL of the /activate or /deactivate
endpoint:

	cfg := ActivateConfig{
		ActivateURI:	"http://veraison.example/endorsement-provisioning/v1/activate",
	}

The user can also supply a custom Client object, for example to appropriately
configure the underlying TLS transport:

	client := &Client{
		HTTPClient: http.Client{
			Transport: myTLSConfig,
		}
	}
	cfg.SetClient(client)

Then the Run method is invoked on the instantiated ActivateConfig object to trigger the exchange.
The user must supply the byte buffer containing the serialized ELM query
(https://github.com/veraison/docs/tree/main/api/endorsement-provisioning#query-format)
and the associated media type:

	err := cfg.Run(elmQueryBuf, "application/vnd.veraison.elm-v1+cbor")

On success err is nil.
*/
package provisioning
