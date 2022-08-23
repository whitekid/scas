package acme

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	acmeclient "scas/client/acme"
	"scas/client/common"
	"scas/pkg/helper/x509x"
	"scas/pkg/testutils"
)

func generateKey(t *testing.T) []byte {
	privateKey, err := x509x.GenerateKey(x509.ECDSAWithSHA256)
	require.NoError(t, err)

	keyDerBytes, err := x509x.EncodePrivateKeyToPEM(privateKey)
	require.NoError(t, err)

	return keyDerBytes
}

func TestNewAccount(t *testing.T) {
	priv := generateKey(t)

	type args struct {
		contact string
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`invalid contact`, args{contact: "mailto:hello@invalid.com"}, true},
		{`valid`, args{contact: "mailto:hello@example.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			client := testutils.Must1(acmeclient.New(newTestServer(ctx, t).URL, priv))

			got, err := client.NewAccount(ctx, &acmeclient.AccountRequest{Contact: []string{tt.args.contact}})
			require.Truef(t, (err != nil) == tt.wantErr, `NewAccount() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
			if tt.wantErr {
				return
			}

			require.NotEmptyf(t, got.ID, "acct: %+v", got)
			require.Regexp(t, `^http.+/accounts/.+`, got.Location)
			require.Regexp(t, `^http.+/accounts/.+/orders`, got.Orders)
		})
	}
}

func TestFindAccountByKey(t *testing.T) {
	priv := generateKey(t)

	type args struct {
		contact string
	}
	tests := [...]struct {
		name string
		args args
	}{
		{`valid`, args{contact: "mailto:hello@example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			client := testutils.Must1(acmeclient.New(newTestServer(ctx, t).URL, priv))

			created, err := client.NewAccount(ctx, &acmeclient.AccountRequest{Contact: []string{tt.args.contact}})
			require.NoError(t, err)

			got, err := client.NewAccount(ctx, &acmeclient.AccountRequest{Contact: []string{tt.args.contact}})
			require.NoError(t, err)
			require.Equal(t, created.ID, got.ID)

			require.Regexp(t, `^http.+/accounts/.+`, got.Location)
			require.Regexp(t, `^http.+/accounts/.+/orders`, got.Orders)
		})
	}
}

func TestUpdateAccount(t *testing.T) {
	priv := generateKey(t)

	type args struct {
		contact string
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`invalid contact`, args{contact: "updated@example.com"}, true},
		{`invalid contact`, args{contact: "mailto:updated@invalid.com"}, true},
		{`valid`, args{contact: "mailto:updated@example.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			client := testutils.Must1(acmeclient.New(newTestServer(ctx, t).URL, priv))

			acct, err := client.NewAccount(ctx, &acmeclient.AccountRequest{Contact: []string{"mailto:hello@example.com"}})
			require.NoError(t, err)

			got, err := client.Account(acct.Location).Update(ctx, &acmeclient.AccountRequest{Contact: []string{tt.args.contact}})
			require.Truef(t, (err != nil) == tt.wantErr, `NewAccount() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
			if tt.wantErr {
				return
			}

			require.Equal(t, got.Contact, []string{tt.args.contact})
			require.Equal(t, acct.ID, got.ID)

			require.Regexp(t, `^http.+/accounts/.+`, got.Location)
			require.Regexp(t, `^http.+/accounts/.+/orders`, got.Orders)
		})
	}
}

func TestTermChanged(t *testing.T) {
	priv := generateKey(t)

	type args struct {
		termUpdateAt time.Time
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`updated`, args{termUpdateAt: time.Now().UTC().Add(-time.Hour)}, true},
		{`valid`, args{termUpdateAt: time.Time{}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			ts := newTestServer(ctx, t)
			client := testutils.Must1(acmeclient.New(ts.URL, priv))

			acct, err := client.NewAccount(ctx, &acmeclient.AccountRequest{Contact: []string{"mailto:hello@example.com"}})
			require.NoError(t, err)

			ts.server.manager.SetTermUpdated(tt.args.termUpdateAt)
			_, err = client.Account(acct.Location).Update(ctx, &acmeclient.AccountRequest{Contact: []string{"mailto:updated@example.com"}})
			require.Truef(t, (err != nil) == tt.wantErr, `NewAccount() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
			if tt.wantErr {
				var p *common.ProblemDetail
				require.ErrorAs(t, err, &p)

				// require.Equal(t, store.ErrUserActionRequired.Status, p.Status)
				require.Regexpf(t, "^http", p.Instance, "problem: %+v", p)
				return
			}
		})
	}
}

func TestAccountKeyChange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	priv := generateKey(t)

	client := testutils.Must1(acmeclient.New(newTestServer(ctx, t).URL, priv))
	acct := testutils.Must1(client.NewAccount(ctx, &acmeclient.AccountRequest{Contact: []string{"mailto:hello@example.com"}}))

	err := client.Account(acct.Location).KeyChange(ctx)
	require.NoError(t, err)

	got, err := client.Account(acct.Location).Update(ctx, &acmeclient.AccountRequest{Contact: []string{"mailto:updated@example.com"}})
	require.NoError(t, err)
	require.Equal(t, "mailto:updated@example.com", got.Contact[0])
}
