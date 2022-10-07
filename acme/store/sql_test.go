package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp"

	"scas/acme/store/models"
	acmeclient "scas/client/acme"
	"scas/client/common"
	"scas/pkg/helper/gormx"
	"scas/pkg/testutils"
)

type testSQL struct {
	*sqlStoreImpl
	proj  *Project
	acct  *Account
	order *Order
	authz *Authz
}

func newFixture(ctx context.Context, t *testing.T, scheme string) *testSQL {
	dbname := testutils.DBName(t)
	var dburl string
	switch scheme {
	case "sqlite":
		os.Remove(dbname + ".db")
		dburl = fmt.Sprintf("sqlite://%s.db", dbname)
	default:
		require.Failf(t, "not supported scheme", scheme)
	}

	s := NewSQLStore(dburl).(*sqlStoreImpl)

	proj := testutils.Must1(s.CreateProject(ctx, &Project{Name: "test project"}))

	acct := testutils.Must1(s.CreateAccount(ctx, &Account{
		AccountResource: acmeclient.AccountResource{
			Status:  acmeclient.AccountStatusValid,
			Contact: []string{"mailto:hello@example.com"},
		},
		Key:       goxp.RandomString(10),
		ProjectID: proj.ID,
	}))

	order := testutils.Must1(s.CreateOrder(ctx, &Order{
		Order: &acmeclient.Order{
			OrderResource: acmeclient.OrderResource{
				Status:      acmeclient.OrderStatusPending,
				Identifiers: []common.Identifier{{Type: common.IdentifierDNS, Value: "server1.acme.127.0.0.1.sslip.io"}},
				NotAfter:    common.TimestampNow().AddDate(1, 0, 0),
				NotBefore:   common.TimestampNow().AddDate(0, 1, 0),
			},
		},
		AccountID: acct.ID,
		ProjectID: proj.ID,
	}))

	authz, err := s.CreateAuthz(ctx, &Authz{
		AccountID:  acct.ID,
		ProjectID:  proj.ID,
		OrderID:    order.ID,
		Status:     acmeclient.AuthzStatusPending,
		Identifier: common.Identifier{Type: common.IdentifierDNS, Value: "server1.acme.127.0.0.1.sslip.io"},
		Expires:    common.TimestampNow().Add(30 * time.Minute),
	})
	require.NoError(t, err)
	require.NotEmpty(t, authz.ID)

	chal, err := s.CreateChallenge(ctx, &Challenge{
		Challenge: &acmeclient.Challenge{
			Type:   acmeclient.ChallengeTypeHttp01,
			Status: acmeclient.ChallengeStatusPending,
		},
		AuthzID:   authz.ID,
		ProjectID: proj.ID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, chal.ID)

	_ = testutils.Must1(s.CreateCertificate(ctx, &Certificate{
		ProjectID: proj.ID,
		OrderID:   order.ID,
		Chain:     goxp.RandomByte(20),
	}))

	return &testSQL{
		sqlStoreImpl: s,
		proj:         proj,
		acct:         acct,
		order:        order,
		authz:        authz,
	}
}

func TestNonce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := newFixture(ctx, t, "sqlite")

	nonce, err := s.CreateNonce(ctx, s.proj.ID)
	require.NoError(t, err)
	require.NotEmpty(t, nonce)

	require.True(t, s.ValidNonce(ctx, s.proj.ID, nonce))

	// create another nonce
	nonce2, err := s.CreateNonce(ctx, s.proj.ID)
	require.NoError(t, err)

	// expire nonce
	require.NoError(t, s.db.Model(&models.Nonce{ID: nonce2, ProjectID: s.proj.ID}).Update("expire", time.Now().UTC().Add(-time.Hour)).Error)
	require.False(t, s.ValidNonce(ctx, s.proj.ID, nonce2))

	require.NoError(t, s.CleanupExpiredNonce(ctx))

	var nonceCount int64
	require.NoError(t, s.db.Model(&models.Nonce{}).Count(&nonceCount).Error)
	require.Equal(t, int64(1), nonceCount)

	require.True(t, s.ValidNonce(ctx, s.proj.ID, nonce))
	require.False(t, s.ValidNonce(ctx, s.proj.ID, nonce2))
}

func TestAccount(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := newFixture(ctx, t, "sqlite")

	{
		got, err := s.GetAccount(ctx, s.proj.ID, s.acct.ID)
		require.NoError(t, err)
		require.Equal(t, s.acct, got)
	}

	{
		got, err := s.GetAccountByKey(ctx, s.proj.ID, s.acct.Key)
		require.NoError(t, err)
		require.Equal(t, s.acct, got)
	}
}

func TestOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := newFixture(ctx, t, "sqlite")

	// create order, authz and challenge
	order, err := s.CreateOrder(ctx, &Order{
		Order: &acmeclient.Order{
			OrderResource: acmeclient.OrderResource{
				Status:      acmeclient.OrderStatusPending,
				Expires:     common.TimestampNow().Add(time.Minute * 30),
				Identifiers: []common.Identifier{{Type: common.IdentifierDNS, Value: "test.charlie.127.0.0.1.sslip.io"}},
				NotAfter:    common.TimestampNow().AddDate(0, 1, 0),
				NotBefore:   common.TimestampNow().AddDate(0, 1, 0),
			},
		},
		ProjectID: s.proj.ID,
		AccountID: s.acct.ID,
	})
	require.NoError(t, err)
	require.NotNil(t, order)
	require.NotEmpty(t, order.ID)
	require.Equal(t, 1, len(order.Identifiers))

	for _, ident := range order.Identifiers {
		authz, err := s.CreateAuthz(ctx, &Authz{
			ProjectID: s.proj.ID,
			AccountID: s.acct.ID,
			OrderID:   order.ID,
			Status:    acmeclient.AuthzStatusPending,
			Expires:   common.TimestampNow().Add(time.Minute * 30),
			Identifier: common.Identifier{
				Type:  ident.Type,
				Value: ident.Value,
			},
			Wildcard: false,
		})
		require.NoError(t, err)
		order.Authz = append(order.Authz, authz.ID)

		chal, err := s.CreateChallenge(ctx, &Challenge{
			ProjectID: s.proj.ID,
			AuthzID:   authz.ID,
			Challenge: &acmeclient.Challenge{
				Type:   acmeclient.ChallengeTypeHttp01,
				Status: acmeclient.ChallengeStatusPending,
			},
		})
		require.NoError(t, err)
		require.NotEmpty(t, chal.ID)
	}

	require.NoError(t, err)

	{
		got, err := s.GetOrder(ctx, order.ID)
		require.NoError(t, err)
		require.Equal(t, order, got)
		require.Equal(t, len(order.Identifiers), len(got.Authz))
		for _, authID := range got.Authz {
			authz, err := s.GetAuthz(ctx, authID)
			require.NoError(t, err)
			require.Equal(t, len(order.Identifiers), len(authz.Challenges))

			for _, chal := range authz.Challenges {
				require.NotEmpty(t, chal.ID)
			}
		}
	}
}

func TestAuthz(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := newFixture(ctx, t, "sqlite")

	got, err := s.GetAuthz(ctx, s.authz.ID)
	require.NoError(t, err)
	require.NotEmpty(t, got.Challenges)

	cert, err := s.CreateCertificate(ctx, &Certificate{
		ProjectID: s.proj.ID,
		OrderID:   s.order.ID,
		Chain:     goxp.RandomByte(100),
	})
	require.NoError(t, err)
	require.NotEmpty(t, cert.ID)

	_, err = s.UpdateAuthzStatus(ctx, s.authz.ID, acmeclient.AuthzStatusValid)
	require.NoError(t, err)
}

func TestChallengeValidate(t *testing.T) {
	type args struct {
		challenge *Challenge
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			`valid`, args{&Challenge{
				Challenge: &acmeclient.Challenge{
					Type:   acmeclient.ChallengeTypeHttp01,
					Status: acmeclient.ChallengeStatusPending,
				},
			}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			s := newFixture(ctx, t, "sqlite")

			tt.args.challenge.AuthzID = s.authz.ID
			tt.args.challenge.ProjectID = s.proj.ID
			got, err := s.CreateChallenge(ctx, tt.args.challenge)
			if gormx.IsSQLError(err) {
				return
			}

			require.Truef(t, (err != nil) == tt.wantErr, `CreateChallenge() failed: error = %+v, wantErr = %v, %T`, err, tt.wantErr, err)
			_ = got
		})
	}
}
