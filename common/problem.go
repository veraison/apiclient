package common

import (
	"fmt"
	"net/http"

	"github.com/moogar0880/problems"
)

type ProblemError struct {
	problems.DefaultProblem
}

func (o *ProblemError) Error() string {
	return fmt.Sprintf("%d %s: %s", o.ProblemStatus(), o.ProblemTitle(), o.Detail)
}

func CheckResponse(res *http.Response, expected ...int) error {
	for _, exp := range expected {
		if res.StatusCode == exp {
			return nil
		}
	}

	if res.Header.Get("Content-Type") == problems.ProblemMediaType {
		var prob ProblemError

		if err := DecodeJSONBody(res, &prob.DefaultProblem); err != nil {
			return fmt.Errorf(
				"could not decode problem response (status %d): %w",
				res.StatusCode,
				err,
			)
		}

		return &prob
	}

	return fmt.Errorf("unexpected HTTP response code %d", res.StatusCode)
}
