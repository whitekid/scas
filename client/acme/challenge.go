package acme

import (
	"context"
	"net/http"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/log"

	"scas/client/common"
)

// Challenge represents authorize service
func (client *ACMEClient) Challenge(endpoint string) *ChallengeService {
	return &ChallengeService{
		client:   client,
		endpoint: endpoint,
	}
}

type ChallengeService struct {
	client   *ACMEClient
	endpoint string
}

// Get get challenge resource
func (svc *ChallengeService) Get(ctx context.Context) (*Challenge, error) {
	log.Debugf("ChallengeService.Do(): %s", svc.endpoint)

	resp, err := svc.client.sendJOSERequest(ctx, http.MethodPost, svc.endpoint, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to get challenge")
	}

	var chal Challenge
	defer resp.Body.Close()
	if err := resp.JSON(&chal); err != nil {
		return nil, err
	}

	if t, err := common.ParseTimestamp(resp.Header.Get("Retry-After")); err == nil {
		chal.RetryAfter = t
	}

	return &chal, nil
}

// VerifyRequest request to validate challenge
func (svc *ChallengeService) VerifyRequest(ctx context.Context) error {
	log.Debugf("ChallengeService.Do(): %s", svc.endpoint)

	_, err := svc.client.sendJOSERequest(ctx, http.MethodPost, svc.endpoint, &struct{}{})
	if err != nil {
		return errors.Wrapf(err, "fail to request challenge")
	}

	return nil
}
