package common

import "fmt"

const MIMEProblemDetail = "application/problem+json"

// ProblemDetail problem details for HTTP api: RFC7807
type ProblemDetail struct {
	Type        string       `json:"type"` // problem type URI reference
	Title       string       `json:"title"`
	Status      int          `json:"status"` // http status code
	Detail      string       `json:"detail,omitempty"`
	Instance    string       `json:"instance,omitempty"` // A URI reference that identifies the specific occurrence of the problem.
	Subproblems []Subproblem `json:"subproblems,omitempty"`
}

func (p *ProblemDetail) Error() string {
	if p.Detail == "" {
		return p.Title
	}
	return fmt.Sprintf("%s: %s", p.Title, p.Detail)
}

type Subproblem struct {
	Type       string     `json:"type"`
	Detail     string     `json:"detail,omitempty"`
	Identifier Identifier `json:"identifier,omitempty" validate:"required,dive"`
}

type Identifier struct {
	Type  IdentifierType `json:"type" validate:"required"`
	Value string         `json:"value" validate:"required"`
}

type IdentifierType string

const (
	IdentifierDNS IdentifierType = "dns"
)
