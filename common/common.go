// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// TODO(tho) make these two configurable
const (
	PollPeriod  = 1 * time.Second
	MaxAttempts = 2
)

const (
	APIStatusFailed     = "failed"
	APIStatusSuccess    = "success"
	APIStatusProcessing = "processing"
	APIStatusComplete   = "complete"
)

func ResolveReference(baseURI, referenceURI string) (string, error) {
	u, err := url.Parse(referenceURI)
	if err != nil {
		return "", fmt.Errorf("parsing reference URI: %w", err)
	}

	if u.IsAbs() {
		return referenceURI, nil
	}

	base, err := url.Parse(baseURI)
	if err != nil {
		return "", fmt.Errorf("parsing base URI: %w", err)
	}

	return base.ResolveReference(u).String(), nil
}

func DecodeJSONBody(res *http.Response, j interface{}) error {
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(&j)
}

// Extract Location header and resolve it to the supplied base (if non-empty)
func ExtractLocation(res *http.Response, base string) (string, error) {
	var err error

	loc := res.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("no Location header found in response")
	}

	if base != "" {
		if loc, err = ResolveReference(base, loc); err != nil {
			return "", fmt.Errorf("the returned Location %q is not a valid URI: %w", loc, err)
		}
	}

	return loc, nil
}
