package manager

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	"scas/acme/store"
	acmeclient "scas/client/acme"
	"scas/client/common"
	"scas/pkg/helper"
	"scas/pkg/testutils"
)

type Fixture struct {
	store.Interface
	proj      *store.Project
	acct      *store.Account
	order     *store.Order
	authz     *store.Authz
	challenge *store.Challenge
}

type fixtureOpts struct {
	noCleanup bool
}

func setupFixture(ctx context.Context, t *testing.T, opts fixtureOpts) *Fixture {
	dbname := testutils.DBName(t.Name())
	if !opts.noCleanup {
		os.Remove(dbname + ".db")
	}

	s := store.NewSQLStore("sqlite://" + dbname + ".db")

	proj, err := s.CreateProject(ctx, &store.Project{
		Name:       "test project",
		CommonName: "charlie.127.0.0.1.sslip.io",
	})
	require.NoError(t, err)

	acct, err := s.CreateAccount(ctx, &store.Account{
		AccountResource: acmeclient.AccountResource{
			Status:  acmeclient.AccountStatusValid,
			Contact: []string{"me@example.com"},
		},
		Key:       base64.RawURLEncoding.EncodeToString(goxp.RandomByte(20)),
		ProjectID: proj.ID,
	})
	require.NoErrorf(t, err, "%+v", err)

	order, err := s.CreateOrder(ctx, &store.Order{
		Order: &acmeclient.Order{
			OrderResource: acmeclient.OrderResource{
				Status:      acmeclient.OrderStatusPending,
				Identifiers: []common.Identifier{{Type: common.IdentifierDNS, Value: "hello.example.com.127.0.0.1.sslip.io"}},
				NotBefore:   common.TimestampNow().Truncate(time.Minute),
				NotAfter:    common.TimestampNow().Truncate(time.Minute),
				Expires:     common.TimestampNow().Truncate(time.Minute).Add(orderTimeout),
			},
		},
		ProjectID: proj.ID,
		AccountID: acct.ID,
	})
	require.NoErrorf(t, err, "%+v", err)

	var authz *store.Authz
	var challenge *store.Challenge
	for _, ident := range order.Identifiers {
		authz, err = s.CreateAuthz(ctx, &store.Authz{
			ProjectID:  proj.ID,
			AccountID:  acct.ID,
			OrderID:    order.ID,
			Status:     acmeclient.AuthzStatusPending,
			Expires:    common.TimestampNow().Add(time.Minute),
			Identifier: ident,
		})
		require.NoErrorf(t, err, "%+v", err)

		challenge, err = s.CreateChallenge(ctx, &store.Challenge{
			Challenge: &acmeclient.Challenge{
				Type:   acmeclient.ChallengeTypeHttp01,
				Status: acmeclient.ChallengeStatusPending,
			},
			ProjectID: proj.ID,
			AuthzID:   authz.ID,
		})
		require.NoError(t, err)
	}

	return &Fixture{
		Interface: s,
		proj:      proj,
		acct:      acct,
		order:     order,
		authz:     authz,
		challenge: challenge,
	}
}

func TestChallenger(t *testing.T) {
	type args struct {
		challengeType acmeclient.ChallengeType
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`valid http01`, args{acmeclient.ChallengeTypeHttp01}, false},
		{`valid dns01`, args{acmeclient.ChallengeTypeDns01}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			s := setupFixture(ctx, t, fixtureOpts{})

			m := New(s.Interface)
			challenger := newChallenger(m, s.Interface)

			errCh := make(chan error)
			defer close(errCh)

			authz := s.authz
			chal := s.challenge
			acct := s.acct

			chal, err := s.UpdateChallengeType(ctx, chal.ID, tt.args.challengeType)
			require.NoError(t, err)

			pub, _ := base64.RawURLEncoding.DecodeString(acct.Key)
			switch tt.args.challengeType {
			case acmeclient.ChallengeTypeHttp01:
				chalServer := testutils.NewChallengeServer(ctx, chal.Token, helper.SHA256Sum(pub))
				os.Setenv("CHALLENGE_HTTP01_SERVER_PORT", chalServer.Port)
			case acmeclient.ChallengeTypeDns01:
				s := newTestDNSServer(ctx, [][]string{{"_acme-challenge." + authz.Identifier.Value, base64.RawURLEncoding.EncodeToString(helper.SHA256Sum(pub))}})
				os.Setenv("CHALLENGE_DNS01_SERVER_ADDR", s.addr)
				defer os.Unsetenv("CHALLENGE_DNS01_SERVER_ADDR")
			}

			go challenger.Start(ctx, errCh)
			go fx.IterChan(ctx, errCh, func(err error) { t.Logf("error: %+v", err) })

			challenger.Enqueue(chal.ID, authz.ID)
			time.Sleep(time.Millisecond * 500) // give some time to try

			chal, _ = s.GetChallenge(ctx, chal.ID)
			require.Equal(t, acmeclient.ChallengeStatusValid, chal.Status)
			require.NotNil(t, chal.Validated)
			authz, _ = s.GetAuthz(ctx, authz.ID)
			require.Equal(t, acmeclient.AuthzStatusValid, authz.Status)
			order, _ := s.GetOrder(ctx, authz.OrderID)
			require.Equal(t, acmeclient.OrderStatusReady, order.Status)
		})
	}
}

func TestChallengeRetry(t *testing.T) {
	type args struct {
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`valid`, args{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			s := setupFixture(ctx, t, fixtureOpts{})

			m := New(s.Interface)
			challenger := newChallenger(m, s.Interface)

			errCh := make(chan error)
			defer close(errCh)

			go challenger.Start(ctx, errCh)
			go fx.IterChan(ctx, errCh, func(err error) {})

			challenger.Enqueue(s.challenge.ID, s.authz.ID)
			time.Sleep(time.Millisecond * 500)

			chal, err := s.GetChallenge(ctx, s.challenge.ID)
			require.NoError(t, err)
			require.Equal(t, acmeclient.ChallengeStatusProcessing, chal.Status)
			require.NotEmpty(t, chal.RetryAfter)
			require.NotEmpty(t, chal.Error, `error should set when retry failed`)

			// request again challenge
			pub, _ := base64.RawURLEncoding.DecodeString(s.acct.Key)
			chalServer := testutils.NewChallengeServer(ctx, chal.Token, helper.SHA256Sum(pub))
			os.Setenv("CHALLENGE_HTTP01_SERVER_PORT", chalServer.Port)

			time.Sleep(challengeRetryInterval)

			chal, err = s.GetChallenge(ctx, s.challenge.ID)
			require.NoError(t, err)
			require.Equal(t, acmeclient.ChallengeStatusValid, chal.Status) // retry 중에는 상태가 변경되지 않음
			require.NotEmpty(t, chal.Error, `error should set when retry failed`)
		})
	}
}

type testDNSServer struct {
	server *dns.Server
	addr   string
}

func newTestDNSServer(ctx context.Context, records [][]string) *testDNSServer {
	addr := fmt.Sprintf("0.0.0.0:%d", goxp.AvailableUdpPort())

	server := &dns.Server{Addr: addr, Net: "udp"}

	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Errorf("error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		server.Shutdown()
	}()

	server.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := &dns.Msg{}
		m.SetReply(r)

		for _, q := range m.Question {
			if q.Qtype == dns.TypeTXT {
				for _, record := range records {
					if dns.Fqdn(record[0]) == q.Name {
						txt := record[1]
						m.Answer = append(m.Answer, &dns.TXT{
							Hdr: dns.RR_Header{
								Name:     q.Name,
								Rrtype:   dns.TypeTXT,
								Class:    dns.ClassINET,
								Ttl:      229,
								Rdlength: uint16(len(txt)),
							},
							Txt: []string{txt},
						})
					}
				}
			}
		}

		w.WriteMsg(m)
	})

	time.Sleep(time.Millisecond * 100) // give some time to startup
	return &testDNSServer{
		server: server,
		addr:   addr,
	}
}

func TestResolver(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := newTestDNSServer(ctx, [][]string{{"_acme-challenge.example.com.", "local-challenge-token"}})

	type args struct {
		q      string
		server string
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
		wantTxt string
	}{
		{`valid local`, args{"_acme-challenge.example.com", s.addr}, false, "local-challenge-token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			got, err := newResolverWithServer(tt.args.server).LookupTXT(ctx, tt.args.q)
			require.Truef(t, (err != nil) == tt.wantErr, `queryTxt() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
			require.NotEmpty(t, got)
			require.Contains(t, got, tt.wantTxt)
		})
	}
}
