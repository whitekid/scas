package acme

import (
	"context"
	"net/http"

	"github.com/pkg/errors"

	"scas/client/common"
)

// Authz represents authorize service
func (client *ACMEClient) Authz(endpoint string) *AuthzService {
	return &AuthzService{
		client:   client,
		endpoint: endpoint,
	}
}

type AuthzService struct {
	client   *ACMEClient
	endpoint string
}

type ChallengeResource struct {
	Status     ChallengeStatus     `json:"status"`
	Expires    *common.Timestamp   `json:"expires"`
	Identifier []common.Identifier `json:"identifier" validate:"dive,required"`
	Challenges []*Challenge        `json:"challenges"`
}

type ChallengeStatus string

const (
	ChallengeStatusPending    ChallengeStatus = "pending"
	ChallengeStatusProcessing ChallengeStatus = "processing"
	ChallengeStatusValid      ChallengeStatus = "valid"
	ChallengeStatusInvalid    ChallengeStatus = "invalid"
)

func (s ChallengeStatus) String() string { return string(s) }

type ChallengeType string

const (
	ChallengeTypeHttp01 ChallengeType = "http-01"
	ChallengeTypeDns01  ChallengeType = "dns-01"
)

func (t ChallengeType) String() string { return string(t) }

type Challenge struct {
	Type      ChallengeType         `json:"type" validate:"required"`
	URL       string                `json:"url"`
	Token     string                `json:"token"`
	Status    ChallengeStatus       `json:"status,omitempty" validate:"required"`
	Validated *common.Timestamp     `json:"validated,omitempty"`
	Error     *common.ProblemDetail `json:"error,omitempty"`

	// data in header
	RetryAfter *common.Timestamp `json:"-"`
}

type AuthzResource struct {
	Status     AuthzStatus       `json:"status"`
	Expires    *common.Timestamp `json:"expires,omitempty"`
	Identifier common.Identifier `json:"identifier" validation:"required,dive"`
	Challenges []*Challenge      `json:"challenges"`
	Wildcard   bool              `json:"wildcard,omitempty"`
}

type Authz struct {
	AuthzResource
	ID string
}

type AuthzStatus string

const (
	AuthzStatusPending     AuthzStatus = "pending"
	AuthzStatusValid       AuthzStatus = "valid"
	AuthzStatusInvalid     AuthzStatus = "invalid"
	AuthzStatusDeactivated AuthzStatus = "deactivated"
	AuthzStatusExpired     AuthzStatus = "expired"
	AuthzStatusRevoked     AuthzStatus = "revoked"
)

func (s AuthzStatus) String() string { return string(s) }

func (svc *AuthzService) Get(ctx context.Context) (*Authz, error) {
	resp, err := svc.client.sendJOSERequest(ctx, http.MethodPost, svc.endpoint, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to request authorize")
	}

	authz := Authz{}
	if err := resp.JSON(&authz.AuthzResource); err != nil {
		return nil, errors.Wrap(err, "fail to decode ressponse")
	}

	u, err := resp.Location()
	if err != nil {
		return nil, errors.Wrap(err, "fail to parse response")
	}
	authz.ID = idFromURI(u.String())

	return &authz, nil
}
