package helper

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp"
)

func TestReadFileOrURL(t *testing.T) {
	type args struct {
		url string
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
		want    []byte
	}{
		{`valid: file`, args{"file://" + goxp.Filename()}, false, MustReadFile(goxp.Filename())},
		{`valid: url`, args{"https://github.com/favicon.ico"}, false, MustHttpGet("https://github.com/favicon.ico")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadFileOrURL(tt.args.url)
			require.Truef(t, (err != nil) == tt.wantErr, `readFileOrURL() failed: error = %v, wantErr = %v`, err, tt.wantErr)

			require.EqualValues(t, tt.want, got)
		})
	}
}

func TestCRLVerifier(t *testing.T) {
	type args struct {
		url string
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`valid`, args{"https://www.daum.net/"}, false},
		{`valid`, args{"https://www.google.com/"}, false},
		{`valid: no crl in leaf`, args{"https://www.ciokorea.com/"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := NewCRLVerifier()

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						VerifyPeerCertificate: verifier.Verify,
					},
				},
			}

			_, err := client.Get(tt.args.url)
			require.Truef(t, (err != nil) == tt.wantErr, `Get() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
		})
	}
}
