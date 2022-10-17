package types

import (
	"time"

	"scas/client/common"
)

type Project struct {
	ID      string
	Name    string
	Created time.Time
}

type CertificateAuthority struct {
	ID        string
	ProjectID string // project id
	Request   string // json encoded create request
	CAID      *string
	Cert      []byte // Certificate as PEM
	Key       []byte // Private as PEM
	Status    common.Status
	Created   time.Time
}

type Certificate struct {
	ID            string
	CAID          string // ca id
	ProjectID     string // project id
	Request       string // json encoded create request
	Status        common.Status
	Cert          []byte // Certificate as PEM
	Key           []byte // Private as PEM
	Chain         []byte
	Created       time.Time
	RevokedAt     *time.Time
	RevokedReason string

	CN string
}
