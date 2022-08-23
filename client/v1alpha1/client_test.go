package v1alpha1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"scas/client/common/x509types"
)

func TestRevokeRequest(t *testing.T) {
	type args struct {
		body []byte
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
		wantReq *RevokeRequest
	}{
		{`valid`, args{[]byte(`{"Reason":"keyCompromise"}`)}, false, &RevokeRequest{Reason: x509types.RevokeKeyCompromise}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(RevokeRequest)
			err := json.Unmarshal(tt.args.body, req)

			require.Truef(t, (err != nil) == tt.wantErr, `doSomething() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
			require.Equal(t, tt.wantReq, req)
		})
	}
}
