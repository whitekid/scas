package manager

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp"
	"github.com/whitekid/goxp/fx"

	"scas/acme/store"
	"scas/api/v1alpha1"
	"scas/certmanager"
	"scas/certmanager/provider"
	certstore "scas/certmanager/store"
	acmeclient "scas/client/acme"
	"scas/client/common"
	scasclient "scas/client/v1alpha1"
	"scas/pkg/helper"
	"scas/pkg/helper/x509x"
	"scas/pkg/testutils"
)

func TestFinalizeOrder(t *testing.T) {
	type args struct {
		req *x509.CertificateRequest
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`valid`, args{&x509.CertificateRequest{
			Subject: pkix.Name{
				SerialNumber: x509x.RandomSerial().String(),
			},
		}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			fixture := setupFixture(ctx, t, fixtureOpts{})
			fixture.UpdateAuthzStatus(ctx, fixture.authz.ID, acmeclient.AuthzStatusValid)
			fixture.UpdateOrderStatus(ctx, fixture.order.ID, acmeclient.OrderStatusReady)

			m := New(fixture.Interface)

			// request using order data
			tt.args.req.DNSNames = fx.Map(fixture.order.Identifiers, func(id common.Identifier) string { return id.Value })
			tt.args.req.Subject.CommonName = tt.args.req.DNSNames[0]

			got, err := m.FinalizeOrder(ctx, fixture.order.ID, tt.args.req)
			require.Truef(t, (err != nil) == tt.wantErr, `FinalizeOrder() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
			if tt.wantErr {
				return
			}

			require.NotEmpty(t, got)
			require.Equal(t, acmeclient.OrderStatusValid, got.Status)

			cert, err := fixture.GetCertificate(ctx, idFromURI(got.Certificate))
			require.NoError(t, err)
			x509cert, err := x509x.ParseCertificate(cert.Chain)
			require.NoError(t, err)

			require.Equal(t, fx.Map(fixture.order.Identifiers, func(id common.Identifier) string { return id.Value }), x509cert.DNSNames)
			require.Equalf(t, fixture.order.NotBefore, common.NewTimestamp(x509cert.NotBefore), "expected=%s, actual=%s", fixture.order.NotBefore.Format(time.RFC3339Nano), x509cert.NotBefore.Format(time.RFC3339Nano))
			require.Equal(t, fixture.order.NotAfter, common.NewTimestamp(x509cert.NotAfter), "expected=%s, actual=%s", fixture.order.NotAfter.Format(time.RFC3339Nano), x509cert.NotAfter.Format(time.RFC3339Nano))
		})
	}
}

func TestFinalizeOrderWithRemoteCA(t *testing.T) {
	type args struct {
		req *x509.CertificateRequest
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`valid`, args{&x509.CertificateRequest{Subject: pkix.Name{SerialNumber: x509x.RandomSerial().String()}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			dbname := testutils.DBName(t.Name()) + "_scas.db"
			dbURL := fmt.Sprintf("sqlite://" + dbname)

			// setup ca service
			repo := certmanager.New(provider.Native(), certstore.NewSQL(dbURL))
			ts := httptest.NewServer(testutils.NewEndpointHandler(v1alpha1.NewWithRepository(repo)))
			go func() {
				<-ctx.Done()
				ts.Close()
			}()
			client := scasclient.New(ts.URL)
			scasProj, err := client.Projects("").Create(ctx, &scasclient.Project{Name: "test project"})
			require.NoError(t, err)

			ca, err := client.Projects(scasProj.ID).CA().Create(ctx, &scasclient.CertificateRequest{
				CommonName:   "example.127.0.0.sslip.io",
				KeyAlgorithm: x509.ECDSAWithSHA256,
				NotAfter:     helper.AfterNow(5, 0, 0),
				NotBefore:    helper.AfterNow(0, 1, 0),
			})
			require.NoError(t, err)

			// setup acme project with scas project
			fixture := setupFixture(ctx, t, fixtureOpts{noCleanup: true})
			proj, err := fixture.CreateProject(ctx, &store.Project{
				Name:              "test project",
				CommonName:        "example.127.0.0.1.sslip.io",
				UseRemoteCA:       true,
				RemoteCAEndpoint:  ts.URL,
				RemoteCAProjectID: scasProj.ID,
				RemoteCAID:        ca.ID,
			})
			require.NoError(t, err)

			acct, err := fixture.CreateAccount(ctx, &store.Account{
				AccountResource: acmeclient.AccountResource{
					Status:  acmeclient.AccountStatusValid,
					Contact: []string{"me@example.com"},
				},
				Key:       base64.RawURLEncoding.EncodeToString(goxp.RandomByte(20)),
				ProjectID: proj.ID,
			})
			require.NoErrorf(t, err, "%+v", err)

			order, err := fixture.CreateOrder(ctx, &store.Order{
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
			for _, ident := range order.Identifiers {
				authz, err = fixture.CreateAuthz(ctx, &store.Authz{
					ProjectID:  proj.ID,
					AccountID:  acct.ID,
					OrderID:    order.ID,
					Status:     acmeclient.AuthzStatusPending,
					Expires:    common.TimestampNow().Add(time.Minute),
					Identifier: ident,
				})
				require.NoErrorf(t, err, "%+v", err)

				_, err = fixture.CreateChallenge(ctx, &store.Challenge{
					Challenge: &acmeclient.Challenge{
						Type:   acmeclient.ChallengeTypeHttp01,
						Status: acmeclient.ChallengeStatusPending,
					},
					ProjectID: proj.ID,
					AuthzID:   authz.ID,
				})
				require.NoError(t, err)
			}

			fixture.UpdateAuthzStatus(ctx, authz.ID, acmeclient.AuthzStatusValid)
			fixture.UpdateOrderStatus(ctx, order.ID, acmeclient.OrderStatusReady)

			m := New(fixture.Interface)

			// request using order data
			tt.args.req.DNSNames = fx.Map(order.Identifiers, func(id common.Identifier) string { return id.Value })
			tt.args.req.Subject.CommonName = tt.args.req.DNSNames[0]

			got, err := m.FinalizeOrder(ctx, order.ID, tt.args.req)
			require.Truef(t, (err != nil) == tt.wantErr, `FinalizeOrder() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
			if tt.wantErr {
				return
			}

			require.NotEmpty(t, got)
			require.Equal(t, acmeclient.OrderStatusValid, got.Status)

			cert, err := fixture.GetCertificate(ctx, idFromURI(got.Certificate))
			require.NoError(t, err)
			x509cert, err := x509x.ParseCertificate(cert.Chain)
			require.NoError(t, err)

			require.Equal(t, fx.Map(order.Identifiers, func(id common.Identifier) string { return id.Value }), x509cert.DNSNames)
			require.Equalf(t, order.NotBefore, common.NewTimestamp(x509cert.NotBefore), "expected=%s, actual=%s", order.NotBefore.Format(time.RFC3339Nano), x509cert.NotBefore.Format(time.RFC3339Nano))
			require.Equal(t, order.NotAfter, common.NewTimestamp(x509cert.NotAfter), "expected=%s, actual=%s", order.NotAfter.Format(time.RFC3339Nano), x509cert.NotAfter.Format(time.RFC3339Nano))
		})
	}
}
