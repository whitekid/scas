package acme

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	acmeclient "scas/client/acme"
)

func TestProject(t *testing.T) {
	priv := generateKey(t)

	type args struct {
		proj *acmeclient.Project
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`valid`, args{&acmeclient.Project{Name: "test"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			fixture := newFixture(t, ctx)

			proj, err := fixture.client.Projects("").Create(ctx, tt.args.proj)
			require.Truef(t, (err != nil) == tt.wantErr, `Projects.Create() failed: error = %+v, wantErr = %v`, err, tt.wantErr)

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
	t.Skip()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fixture := newFixture(t, ctx)

	proj := fixture.proj
	err := fixture.client.Projects(proj.ID).Term().Update(ctx, "updated term of service")
	require.NoError(t, err)

	term, err := fixture.client.Projects(proj.ID).Term().Get(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, term)
}
