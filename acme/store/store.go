package store

import (
	"context"
	"time"

	acmeclient "scas/client/acme"
	"scas/client/common"
	"scas/client/common/x509types"
)

type Interface interface {
	CreateProject(ctx context.Context, proj *Project) (*Project, error)
	GetProject(ctx context.Context, projID string) (*Project, error)

	CreateTerm(ctx context.Context, projID string, term *Term) (*Term, error)
	GetTerm(ctx context.Context, projID string, termID string) (*Term, error)
	UpdateTerm(ctx context.Context, projID string, term *Term) error
	ActivateTerm(ctx context.Context, projID string, termID string) error

	CreateNonce(ctx context.Context, projID string) (string, error) // create new nonce
	ValidNonce(ctx context.Context, projID string, nonce string) bool
	// CleanupExpiredNonce cleanup expired nonce
	CleanupExpiredNonce(ctx context.Context) error

	CreateAccount(ctx context.Context, account *Account) (*Account, error)
	ListAccount(ctx context.Context, opts ListAccountOpts) ([]*Account, error)
	GetAccount(ctx context.Context, projID string, acctID string) (*Account, error)
	GetAccountByKey(ctx context.Context, projID string, key string) (*Account, error)
	UpdateAccountContact(ctx context.Context, projID string, acctID string, contacts []string) (*Account, error)
	UpdateAccountKey(ctx context.Context, projID string, acctID string, key string) (*Account, error)
	UpdateAccountStatus(ctx context.Context, projID string, acctID string, status acmeclient.AccountStatus) (*Account, error)

	CreateOrder(ctx context.Context, order *Order) (*Order, error)
	GetOrder(ctx context.Context, orderID string) (*Order, error)
	UpdateOrderStatus(ctx context.Context, orderID string, status acmeclient.OrderStatus) (*Order, error)

	CreateAuthz(ctx context.Context, auth *Authz) (*Authz, error)
	ListAuthz(ctx context.Context, opts ListAuthzOpts) ([]*Authz, error)
	GetAuthz(ctx context.Context, authzID string) (*Authz, error)
	UpdateAuthzStatus(ctx context.Context, authzID string, status acmeclient.AuthzStatus) (*Authz, error)

	CreateChallenge(ctx context.Context, chal *Challenge) (*Challenge, error)
	ListChallenges(ctx context.Context, opts ListChallengesOpts) ([]*Challenge, error)
	GetChallenge(ctx context.Context, chalID string) (challenge *Challenge, err error)
	UpdateChallengeStatus(ctx context.Context, chalID string, status acmeclient.ChallengeStatus, validated *common.Timestamp) (*Challenge, error)
	UpdateChallengeType(ctx context.Context, chalID string, chalType acmeclient.ChallengeType) (*Challenge, error)
	UpdateChallengeError(ctx context.Context, chalID string, e error, retryAfter time.Time) (*Challenge, error)

	CreateCertificate(ctx context.Context, cert *Certificate) (*Certificate, error)
	ListCertificate(ctx context.Context, opts ListCertificateOpts) ([]*Certificate, error)
	GetCertificate(ctx context.Context, certID string) (*Certificate, error)
	// Get certificate by certificate sha256 digest of pem format
	GetCertificateBySum(ctx context.Context, sum string) (*Certificate, error)
	RevokeCertificate(ctx context.Context, certID string, reason x509types.RevokeReason) (*Certificate, error)
}

const (
	nonceTimeout = time.Minute * 30
)

type Account struct {
	acmeclient.AccountResource `validate:"required,dive"`

	ID          string `validate:"eq="`
	ProjectID   string `validate:"required"`
	Key         string `validate:"required"` // account public key, base64 encoded
	TermAgreeAt time.Time
}

type Order struct {
	*acmeclient.Order `validate:"required"`
	AccountID         string `validate:"required"`
	ProjectID         string `validate:"required"`
}

type Authz struct {
	ID        string `validate:"eq="`
	ProjectID string `validate:"required"`
	AccountID string
	OrderID   string

	Status     acmeclient.AuthzStatus `json:"status" validate:"required"`
	Expires    *common.Timestamp      `json:"expires,omitempty"`
	Identifier common.Identifier      `json:"identifier" validate:"required,dive"`
	Challenges []*Challenge           `json:"challenges" validate:"dive"`
	Wildcard   bool                   `json:"wildcard,omitempty"`
}

type Challenge struct {
	*acmeclient.Challenge `validate:"dive"`
	ID                    string `validate:"eq="`
	ProjectID             string `validate:"required"`
	AuthzID               string `validate:"required"`
}

type Certificate struct {
	ID           string `validate:"eq="`
	ProjectID    string `validate:"required"`
	OrderID      string `validate:"required"`
	Chain        []byte `validate:"required"` // certificate chain PEM format
	Hash         string
	RevokeReason x509types.RevokeReason
	RevokedAt    *common.Timestamp
}
