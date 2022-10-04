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

func newFixture(t *testing.T, ctx context.Context) *Fixture {
	server := newTestServer(ctx, t)
	client := acmeclient.NewClient(server.URL, nil)
	proj := testutils.Must1(client.Projects().Create(ctx, &acmeclient.Project{Name: "test"}))

	priv := generateKey(t)
	acme := testutils.Must1(client.ACME(proj.ACMEEndpoint, priv))
	acct := testutils.Must1(acme.NewAccount(ctx, &acmeclient.AccountRequest{Contact: []string{"mailto:hello@example.com"}}))

	return &Fixture{
		ACMEClient: acme,
		server:     server,
		acct:       acct,
	}
}

type Fixture struct {
	*acmeclient.ACMEClient
	server *TestServer
	acct   *acmeclient.Account
}

func generateKey(t *testing.T) []byte {
	privateKey, err := x509x.GenerateKey(x509.ECDSAWithSHA256)
	require.NoError(t, err)

	keyDerBytes, err := x509x.EncodePrivateKeyToPEM(privateKey)
	require.NoError(t, err)

	return keyDerBytes
}

func TestNewAccount(t *testing.T) {
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

			client := newFixture(t, ctx)

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

			client := newFixture(t, ctx)

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

			client := newFixture(t, ctx)

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

			client := newFixture(t, ctx)

			acct, err := client.NewAccount(ctx, &acmeclient.AccountRequest{Contact: []string{"mailto:hello@example.com"}})
			require.NoError(t, err)

			client.server.server.manager.SetTermUpdated(tt.args.termUpdateAt)
			_, err = client.Account(acct.Location).Update(ctx, &acmeclient.AccountRequest{Contact: []string{"mailto:updated@example.com"}})
			require.Truef(t, (err != nil) == tt.wantErr, `NewAccount() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
			if tt.wantErr {
				var p *common.ProblemDetail
				require.ErrorAs(t, err, &p)

				// require.Equal(t, store.ErrUserActionRequired.Status, p.Status)
				require.Regexpf(t, "^http", p.Instance, "instance: %s", p.Instance)
				return
			}
		})
	}
}

func TestAccountKeyChange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := newFixture(t, ctx)

	err := client.Account(client.acct.Location).KeyChange(ctx)
	require.NoError(t, err)

	got, err := client.Account(client.acct.Location).Update(ctx, &acmeclient.AccountRequest{Contact: []string{"mailto:updated@example.com"}})
	require.NoError(t, err)
	require.Equal(t, "mailto:updated@example.com", got.Contact[0])
}

func TestAccountDeactive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := newFixture(t, ctx)

	err := client.Account(client.acct.Location).Deactive(ctx)
	require.NoError(t, err)

	err = client.Account(client.acct.Location).KeyChange(ctx)
	require.Contains(t, err.Error(), "Unauthorized")

	_, err = client.Account(client.acct.Location).Update(ctx, &acmeclient.AccountRequest{Contact: []string{"mailto:updated@example.com"}})
	require.Contains(t, err.Error(), "Unauthorized")
}
