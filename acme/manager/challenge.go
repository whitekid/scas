package manager

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"
	"github.com/whitekid/goxp/request"
	"github.com/whitekid/goxp/retry"

	"scas/acme/store"
	acmeclient "scas/client/acme"
	"scas/client/common"
	"scas/pkg/helper"
)

const (
	httpChallengeTimeout   = time.Millisecond * 500
	dnsChallengeTimeout    = time.Millisecond * 500
	challengeRetryInterval = time.Second
)

func (m *Manager) GetChallenge(ctx context.Context, chalID string) (*store.Challenge, error) {
	return m.store.GetChallenge(ctx, chalID)
}

func (m *Manager) RequestChallenge(ctx context.Context, chalID string) error {
	challenge, err := m.store.GetChallenge(ctx, chalID)
	if err != nil {
		return err
	}

	if challenge.Status != acmeclient.ChallengeStatusPending {
		return store.ErrBadChallengeStatus
	}

	authz, err := m.store.GetAuthz(ctx, challenge.AuthzID)
	if err != nil {
		return err
	}

	if authz.Expires.Before(time.Now()) {
		return store.ErrAuthzExpired
	}

	m.challenger.Enqueue(challenge.ID, authz.ID)

	return nil
}

func (m *Manager) StartChallengeLoop(ctx context.Context, errCh chan<- error) {
	m.challenger.Start(ctx, errCh)
}

func (m *Manager) UpdateChallengeStatus(ctx context.Context, chalID string, authzID string, status acmeclient.ChallengeStatus) error {
	authz, err := m.store.GetAuthz(ctx, authzID)
	if err != nil {
		return err
	}

	if _, err := m.store.UpdateChallengeStatus(ctx, chalID, acmeclient.ChallengeStatusValid, common.TimestampNow()); err != nil {
		return err
	}

	if status != acmeclient.ChallengeStatusValid {
		return nil
	}

	// check all challenges were verified
	challenges, err := m.store.ListChallenges(ctx, store.ListChallengesOpts{
		AuthzID: authzID,
		Status:  status,
	})
	if err != nil {
		return err
	}

	if len(authz.Challenges) == len(challenges) {
		log.Infof("all challenge for authz %s was verified", authzID)
		m.store.UpdateAuthzStatus(ctx, authz.ID, acmeclient.AuthzStatusValid)
	}

	// check all authorization were verified
	allValid := true
	order, err := m.store.GetOrder(ctx, authz.OrderID)
	if err != nil {
		return err
	}

	for _, authURI := range order.Authz {
		auth, err := m.store.GetAuthz(ctx, idFromURI(authURI))
		if err != nil {
			panic("authorization was removed... may be expired!")
		}
		if auth.Status != acmeclient.AuthzStatusValid {
			allValid = false
			break
		}
	}

	if allValid {
		log.Infof("all authorization for order %s were verified, turn to ready status", order.ID)
		if _, err := m.store.UpdateOrderStatus(ctx, order.ID, acmeclient.OrderStatusReady); err != nil {
			return err
		}
	}
	return nil
}

type challengeInfo struct {
	challengeID string
	authzID     string
}

type Challenger struct {
	manager *Manager
	store   store.Interface // Depreciated please remove this

	enqueue func(challengeID string, authzID string)
}

func newChallenger(manager *Manager, store store.Interface) *Challenger {
	return &Challenger{
		manager: manager,
		store:   store,
	}
}

// Start start challenger loop until context done
func (c *Challenger) Start(ctx context.Context, errCh chan<- error) {
	chalCh := make(chan *challengeInfo, 10)
	defer close(chalCh)

	go fx.IterChan(ctx, chalCh, func(info *challengeInfo) {
		if err := c.challenge(ctx, info.challengeID, info.authzID); err != nil {
			errCh <- err

			retryAfter := time.Now().UTC().Add(challengeRetryInterval)
			if _, err := c.store.UpdateChallengeError(ctx, info.challengeID, err, retryAfter); err != nil {
				errCh <- err
			}

			log.Infof("challenge %s failed: error=%s, will be retry at %s", info.challengeID, err, retryAfter)
			go helper.After(ctx, time.Until(retryAfter), func() { c.enqueue(info.challengeID, info.authzID) })
		}
	})

	c.enqueue = func(challengeID string, authzID string) {
		chal, err := c.store.UpdateChallengeStatus(ctx, challengeID, acmeclient.ChallengeStatusProcessing, nil)
		if err != nil {
			errCh <- err
		}

		chalCh <- &challengeInfo{
			challengeID: chal.ID,
			authzID:     authzID,
		}
	}

	<-ctx.Done()
}

func (c *Challenger) Enqueue(challengeID string, authzID string) {
	if c.enqueue == nil {
		go retry.New().Backoff(time.Millisecond*50, 1.0).Limit(100).
			Do(context.Background(), func() error {
				if c.enqueue == nil {
					return errors.New("queue not ready")
				}

				c.enqueue(challengeID, authzID)
				return nil
			})
	} else {
		c.enqueue(challengeID, authzID)
	}
}

func (c *Challenger) challenge(ctx context.Context, challengeID string, authzID string) error {
	chal, err := c.store.GetChallenge(ctx, challengeID)
	if err != nil {
		return errors.Wrapf(err, "fail to challenge")
	}

	authz, err := c.store.GetAuthz(ctx, authzID)
	if err != nil {
		return errors.Wrapf(err, "fail to challenge")
	}

	switch chal.Type {
	case acmeclient.ChallengeTypeHttp01:
		if err := c.challangeHttp01(ctx, chal, authz); err != nil {
			return err
		}
	case acmeclient.ChallengeTypeDns01:
		if err := c.challengeDns01(ctx, chal, authz); err != nil {
			return err
		}
	default:
		return errors.Errorf("Unsupported challenge type: %s", chal.Type)
	}

	if err := c.manager.UpdateChallengeStatus(ctx, chal.ID, authzID, acmeclient.ChallengeStatusValid); err != nil {
		return err
	}

	return nil
}

// challengeHttp01 verify http
func (c *Challenger) challangeHttp01(ctx context.Context, chal *store.Challenge, authz *store.Authz) error {
	log.Debugf("challangeHTTP01(): type=%s, value=%s, token=%s", authz.Identifier.Type, authz.Identifier.Value, chal.Token)

	if chal.Token == "" {
		return errors.New("token required")
	}

	port := os.Getenv("CHALLENGE_HTTP01_SERVER_PORT")
	if port != "" {
		port = ":" + port
	}

	parts := strings.SplitN(authz.Identifier.Value, ".", 2)
	url := fmt.Sprintf("http://%s%s/.well-known/acme-challenge/%s", parts[1], port, chal.Token)

	ctx, cancel := context.WithTimeout(ctx, httpChallengeTimeout)
	defer cancel()

	log.Debugf("challenge http-01: %s", url)
	resp, err := request.Get(url).Do(ctx)
	if err != nil {
		return errors.Wrapf(store.ErrIncorrectResponse, "challenge request failed: %s", err)
	}

	if !resp.Success() {
		return errors.Wrapf(store.ErrIncorrectResponse, "challenge response failed with status %d ", resp.StatusCode)
	}

	parts = strings.SplitN(resp.String(), ".", 2)
	if len(parts) != 2 {
		return errors.Wrapf(store.ErrIncorrectResponse, "bad signature format")
	}

	token, thumbprint := parts[0], parts[1]
	if token != chal.Token {
		return store.ErrIncorrectResponse
	}

	acct, err := c.store.GetAccount(ctx, authz.AccountID)
	if err != nil {
		return err
	}

	key, err := base64.RawURLEncoding.DecodeString(acct.Key)
	if err != nil {
		return errors.Wrapf(err, "account key decode failed")
	}

	acctThumbprint := base64.RawURLEncoding.EncodeToString(helper.SHA256Sum(key))
	if thumbprint != acctThumbprint {
		return errors.Wrapf(store.ErrIncorrectResponse, "signature mismatch: %s", thumbprint)
	}

	return nil
}

// challengeDns01 verify DNS
func (c *Challenger) challengeDns01(ctx context.Context, chal *store.Challenge, authz *store.Authz) error {
	addr := os.Getenv("CHALLENGE_DNS01_SERVER_ADDR")
	name := "_acme-challenge." + authz.Identifier.Value
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}

	log.Infof("challengeDNS01(): name:%s, addr=%s", name, addr)

	ctx, cancel := context.WithTimeout(ctx, dnsChallengeTimeout)
	defer cancel()

	records, err := newResolverWithServer(addr).LookupTXT(ctx, name)
	if err != nil {
		return errors.Wrapf(store.ErrIncorrectResponse, "%s", err)
	}

	acct, err := c.store.GetAccount(ctx, authz.AccountID)
	if err != nil {
		return err
	}

	key, err := base64.RawURLEncoding.DecodeString(acct.Key)
	if err != nil {
		return errors.Wrapf(err, "account key decode failed")
	}

	digest := base64.RawURLEncoding.EncodeToString(helper.SHA256Sum(key))

	if !fx.Contains(records, digest) {
		log.Debugf("txt=%s, digest=%s", records, digest)
		return store.ErrIncorrectResponse
	}

	return nil
}

func newResolverWithServer(server string) *net.Resolver {
	return &net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if server != "" {
				address = server
			}
			d := &net.Dialer{}
			return d.DialContext(ctx, network, address)
		},
	}
}
