package gormx

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
	type args struct {
		dburl string
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`sqlite`, args{dburl: "sqlite://test.db"}, false},
		{`mysql tls`, args{dburl: "mysql://secure_user@127.0.0.1:3306/?tls=custom"}, false},
		{`mysql tls with trusted ca`, args{dburl: "mysql://x509_user@127.0.0.1:3306/?tls=custom"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := os.LookupEnv("GITHUB_ACTION"); ok {
				t.Skip()
			}

			// load client certificate
			if strings.HasPrefix(tt.args.dburl, "mysql://") {
				rootCertPool := x509.NewCertPool()
				pem, err := os.ReadFile("/usr/local/var/mysql/ca.pem")
				require.NoError(t, err)

				require.True(t, rootCertPool.AppendCertsFromPEM(pem), "Failed to append PEM.")

				clientCert := make([]tls.Certificate, 0, 1)
				certs, err := tls.LoadX509KeyPair("/usr/local/var/mysql/client-cert.pem", "/usr/local/var/mysql/client-key.pem")
				require.NoError(t, err)

				clientCert = append(clientCert, certs)
				mysql.RegisterTLSConfig("custom", &tls.Config{
					RootCAs:            rootCertPool,
					Certificates:       clientCert,
					InsecureSkipVerify: true,
				})

				defer mysql.DeregisterTLSConfig("custom")
			}

			db, err := Open(tt.args.dburl)
			require.NoError(t, err)
			require.NotEmpty(t, db)
		})
	}
}
