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

			ts := newTestServer(ctx, t)

			client := acmeclient.NewClient(ts.URL, nil)
			proj, err := client.Projects().Create(ctx, tt.args.proj)
			require.Truef(t, (err != nil) == tt.wantErr, `Projects.Create() failed: error = %+v, wantErr = %v`, err, tt.wantErr)

			require.NotEmpty(t, proj.ID)
			require.NotEmpty(t, proj.ACMEEndpoint)
			require.NotEmpty(t, proj.CreatedAt)
			require.Equal(t, tt.args.proj.Name, proj.Name)

			got, err := client.Projects().Get(ctx, proj.ID)
			require.NoError(t, err)
			require.Equal(t, proj, got)

			acme, err := client.ACME(proj.ACMEEndpoint, priv)
			require.NoError(t, err)
			_ = acme
		})
	}
}
