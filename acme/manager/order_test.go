package manager

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp/fx"

	acmeclient "scas/client/acme"
	"scas/client/common"
	"scas/pkg/helper/x509x"
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

			fixture := setupFixture(ctx, t)
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
