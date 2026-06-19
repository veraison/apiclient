// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

/*
Package coserv implements a client for the CoSERV API as defined in
draft-howard-rats-coserv.

# Discovery

To obtain the service’s capabilities and the request‑response endpoint URL,
use DiscoveryConfig:

	cfg := &DiscoveryConfig{}
	if err := cfg.SetDiscoveryURI("https://veraison.example"); err != nil {
		// handle error
	}
	cfg.SetIsInsecure(true) // optional: skip TLS verification
	cfg.EnableCache(true)   // optional: enable HTTP caching (RFC 9111)
	if err := cfg.SetCerts([]string{"/path/to/ca.pem"}); err != nil {
		// handle error
	}

	result, err := cfg.Run()
	if err != nil {
		// handle error
	}

	// result contains the full discovery document and the pre‑computed query endpoint URL
	queryURL := result.QueryEndpointURL   // e.g. "https://veraison.example/endorsement-distribution/v1/coserv/{query}"
	doc := result.DiscoveryDocument       // may be used to inspect capabilities or verification keys

Note: the discovery endpoint is always "/.well-known/coserv-configuration", and the client
uses url.URL.JoinPath to construct the absolute URL from the base URI. The discovery
document is validated according to the spec (e.g., the "CoSERVRequestResponse" endpoint
must be present and its URL must end with "{query}").

# Query Execution

Once user have the request‑response URL template (must end with the "{query}" placeholder),
create a QueryConfig:

	qcfg := &QueryConfig{}
	if err := qcfg.SetRequestResponseURI(queryURL); err != nil {
		// handle error
	}

Optionally configure TLS, caching, authentication, or a custom HTTP client:

	qcfg.SetCerts([]string{"/path/to/ca.pem"})
	qcfg.SetIsInsecure(true) // optional: skip TLS verification
	qcfg.EnableCache(true)   // optional: enable HTTP caching (RFC 9111)
	qcfg.SetAuth(myAuthenticator)

Build a CoSERV query using the github.com/veraison/corim/coserv package:

	query, err := coserv.NewCoserv(profile, queryParams)
	if err != nil {
		// handle error
	}

Execute the query:

	// For an unsigned result (CBOR)
	coservResult, err := qcfg.RunQueryForUnsignedResponse(query)
	if err != nil {
		// handle error
	}

	// For a signed result (COSE)
	msg, err := qcfg.RunQueryForSignedResponse(query)
	if err != nil {
		// handle error
	}
	// user can verify the signature and extract the payload:
	extracted, err := ExtractCoservFromSignedResponse(msg, []cose.Verifier{myVerifier})

	// Or use the convenience method that does both:
	coservExtracted, err := qcfg.RunQueryForExtractedSignedResponse(query, []cose.Verifier{myVerifier})

All methods except RunQueryForSignedResponse return a populated Coserv object (with Results) on success, or an error on failure.

# Note on custom HTTP clients

If user provide a custom client via qcfg.SetClient(), user is responsible for ensuring
that the client's transport matches the URL scheme (HTTP or HTTPS) used in the
request template. The library does not validate this consistency.

Once a client has been initialized - either by passing a custom client instance, or by using a QueryConfig -  it can only be modified
by passing a new custom client. Modifying the QueryConfig won't update the existing client.

# Example usage with discovery and query combined

	// 1. Discover
	discoCfg := &DiscoveryConfig{}
	_ = discoCfg.SetDiscoveryURI("https://veraison.example")
	discoResult, err := discoCfg.Run()
	if err != nil {
		log.Fatal(err)
	}

	// 2. Build query
	profile := "tag:example.com,2025:my-profile#1.0"
	envSelector := coserv.NewEnvironmentSelector()
	// ... populate envSelector

	queryParams := coserv.Query{
		ArtifactType:        coserv.ArtifactTypeReferenceValues,
		EnvironmentSelector: *envSelector,
		ResultType:          coserv.ResultTypeBoth,
	}
	query, err := coserv.NewCoserv(profile, queryParams)
	if err != nil {
		log.Fatal(err)
	}

	// 3. Execute signed query with verification
	qcfg := &QueryConfig{}
	_ = qcfg.SetRequestResponseURI(discoResult.QueryEndpointURL)
	msg, err := qcfg.RunQueryForSignedResponse(query)
	if err != nil {
		log.Fatal(err)
	}

	// Populate verifiers from discovery document keys (e.g., from doc.VerificationKeyJwk)
	var verifiers []cose.Verifier
	// ... parse JWKs to create verifiers

	extracted, err := ExtractCoservFromSignedResponse(msg, verifiers)
	if err != nil {
		log.Fatal(err)
	}
*/
package coserv
