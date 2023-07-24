package management

import (
	"time"

	"github.com/google/uuid"
)

// Policy allows enforcing additional constraints on top of the regular
// attestation schemes.
type Policy struct {
	// UUID is the unque identifier associated with this specific instance
	// of a policy.
	UUID uuid.UUID `json:"uuid"`

	// CTime is the creationg time of this policy.
	CTime time.Time `json:"ctime"`

	// Name is the name of this policy. It's a short descritor for the
	// rules in this policy.
	Name string `json:"name"`

	// Type identifies the policy engine used to evaluate the policy, and
	// therfore dictates how the Rules should be interpreted.
	Type string `json:"type"`

	// Rules of the policy to be interpreted and execute by the policy
	// agent.
	Rules string `json:"rules"`

	// Active indicates whether this policy instance is currently active
	// for the associated key.
	Active bool `json:"active"`
}
