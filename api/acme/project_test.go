package acme

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	acmeclient "scas/client/acme"
	"scas/pkg/helper"
)

func TestProjectCreate(t *testing.T) {
	priv := generateKey(t)

	type args struct {
		proj *acmeclient.Project
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`valid`, args{&acmeclient.Project{Name: "test", CommonName: "charlie.127.0.0.1.sslip.io"}}, false},
		{`remote CA`, args{&acmeclient.Project{Name: "test", CommonName: "charlie.127.0.0.1.sslip.io",
			UseRemoteCA: true, RemoteCAEndpoint: "http://example.com/xx", RemoteCAProjectID: helper.NewID(), RemoteCAID: helper.NewID()}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			fixture := newFixture(t, ctx)

			proj, err := fixture.client.Projects("").Create(ctx, tt.args.proj)
			require.Truef(t, (err != nil) == tt.wantErr, `Projects.Create() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
			require.Equal(t, tt.args.proj.Name, proj.Name)
			require.Equal(t, tt.args.proj.CommonName, proj.CommonName)
			require.Equal(t, tt.args.proj.CommonName, proj.CommonName)
			require.Equal(t, tt.args.proj.UseRemoteCA, proj.UseRemoteCA)
			require.Equal(t, tt.args.proj.RemoteCAEndpoint, proj.RemoteCAEndpoint)
			require.Equal(t, tt.args.proj.RemoteCAProjectID, proj.RemoteCAProjectID)
			require.Equal(t, tt.args.proj.RemoteCAID, proj.RemoteCAID)

			require.NotEmpty(t, proj.ID)
			require.NotEmpty(t, proj.ACMEEndpoint)
			require.NotEmpty(t, proj.CreatedAt)
			require.Equal(t, tt.args.proj.Name, proj.Name)

			got, err := fixture.client.Projects(proj.ID).Get(ctx)
			require.NoError(t, err)
			require.Equal(t, proj, got)

			acme, err := fixture.client.ACME(proj.ACMEEndpoint, priv) // TODO 어라?... 없는 키 일텐데....
			require.NoError(t, err)
			_ = acme
		})
	}
}

func TestProjectTerms(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fixture := newFixture(t, ctx)
	termSvc := fixture.client.Projects(fixture.proj.ID).Term()

	// create first term of service
	term := &acmeclient.Term{Content: "term of service"}
	created, err := termSvc.Update(ctx, term)
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)
	require.Equal(t, "term of service", created.Content)
	require.False(t, created.Active)

	{
		got, err := termSvc.Get(ctx, created.ID)
		require.NoError(t, err)
		require.NotEmpty(t, got.ID)
		require.False(t, got.Active)

		proj, err := fixture.client.Projects(fixture.proj.ID).Get(ctx)
		require.NoError(t, err)
		require.Empty(t, proj.TermID)
	}

	// activate
	term.Content = "updated term of service"
	term.Active = true
	activated, err := termSvc.Update(ctx, term)
	require.NoError(t, err)

	{
		got, err := termSvc.Get(ctx, activated.ID)
		require.NoError(t, err)
		require.NotEmpty(t, got.ID)
		require.True(t, got.Active)

		proj, err := fixture.client.Projects(fixture.proj.ID).Get(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, proj.TermID)
	}
}
