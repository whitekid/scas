package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lithammer/shortuuid/v4"
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
}

func newSQL(t *testing.T, scheme string) *testSQL {
	dbname := testutils.DBName(t)
	var dburl string
	switch scheme {
	case "sqlite":
		os.Remove(dbname + ".db")
		dburl = fmt.Sprintf("sqlite://%s.db", dbname)
	default:
		require.Failf(t, "not supported scheme", scheme)
	}

	s := &testSQL{sqlStoreImpl: NewSQLStore(dburl).(*sqlStoreImpl)}
	return s
}

func TestNonce(t *testing.T) {
	s := newSQL(t, "sqlite")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nonce, err := s.CreateNonce(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, nonce)

	require.True(t, s.ValidNonce(ctx, nonce))

	// create another nonce
	nonce2, err := s.CreateNonce(ctx)
	require.NoError(t, err)

	// expire nonce
	require.NoError(t, s.db.Model(&models.Nonce{ID: nonce2}).Update("expire", time.Now().UTC().Add(-time.Hour)).Error)
	require.False(t, s.ValidNonce(ctx, nonce2))

	require.NoError(t, s.CleanupExpiredNonce(ctx))

	var nonceCount int64
	require.NoError(t, s.db.Model(&models.Nonce{}).Count(&nonceCount).Error)
	require.Equal(t, int64(1), nonceCount)

	require.True(t, s.ValidNonce(ctx, nonce))
	require.False(t, s.ValidNonce(ctx, nonce2))
}

func TestAccount(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := newSQL(t, "sqlite")

	acct, err := s.CreateAccount(ctx, &Account{
		AccountResource: acmeclient.AccountResource{
			Status:  acmeclient.AccountStatusValid,
			Contact: []string{"contact@example.com"},
		},
		Key: goxp.RandomString(10),
	})
	require.NoError(t, err)
	require.NotNil(t, acct)
	require.NotEmpty(t, acct.ID)

	{
		got, err := s.GetAccount(ctx, acct.ID)
		require.NoError(t, err)
		require.Equal(t, acct, got)
	}

	{
		got, err := s.GetAccountByKey(ctx, acct.Key)
		require.NoError(t, err)
		require.Equal(t, acct, got)
	}
}

func TestOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := newSQL(t, "sqlite")

	acct, err := s.CreateAccount(ctx, &Account{
		AccountResource: acmeclient.AccountResource{
			Status:  acmeclient.AccountStatusValid,
			Contact: []string{"hello@example.com"},
		},
		Key: goxp.RandomString(20),
	})
	require.NoError(t, err)

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
		AccountID: acct.ID,
	})
	require.NoError(t, err)
	require.NotNil(t, order)
	require.NotEmpty(t, order.ID)
	require.Equal(t, 1, len(order.Identifiers))

	// TODO sequence diagram을 한 번 그려봐야겠음.
	// TODO create authz
	for _, ident := range order.Identifiers {
		authz, err := s.CreateAuthz(ctx, &Authz{
			AccountID: acct.ID,
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
			AuthzID: authz.ID,
			Challenge: &acmeclient.Challenge{
				Type:   acmeclient.ChallengeHTTP01,
				Token:  shortuuid.New(),
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
			`invalid token`, args{&Challenge{
				Challenge: &acmeclient.Challenge{
					Type:   acmeclient.ChallengeHTTP01,
					Status: acmeclient.ChallengeStatusPending,
				},
				AuthzID: shortuuid.New(),
			}}, true},
		{
			`valid`, args{&Challenge{
				Challenge: &acmeclient.Challenge{
					Type:   acmeclient.ChallengeHTTP01,
					Token:  shortuuid.New(),
					Status: acmeclient.ChallengeStatusPending,
				},
				AuthzID: shortuuid.New(),
			}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			s := newSQL(t, "sqlite")

			got, err := s.CreateChallenge(ctx, tt.args.challenge)

			if gormx.IsSQLError(err) {
				return
			}

			require.Truef(t, (err != nil) == tt.wantErr, `CreateChallenge() failed: error = %+v, wantErr = %v, %T`, err, tt.wantErr, err)
			_ = got
		})
	}

}
