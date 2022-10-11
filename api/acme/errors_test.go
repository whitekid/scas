package acme

import (
	"context"
	"net/http"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp/request"

	"scas/acme/store"
	"scas/client/common"
	"scas/pkg/helper"
)

func TestError(t *testing.T) {
	type args struct {
		err error
	}
	tests := [...]struct {
		name        string
		args        args
		wantProblem *common.ProblemDetail
	}{
		{
			`unknown`, args{err: errors.New("server has a problem")}, &common.ProblemDetail{
				Type:   "urn:ietf:params:acme:error:serverInternal",
				Status: http.StatusInternalServerError,
				Title:  "the server experienced an internal error",
				Detail: "server has a problem",
			}},
		{
			`errBadCSR`, args{err: store.ErrBadCSR}, &common.ProblemDetail{
				Type:   "urn:ietf:params:acme:error:badCSR",
				Status: http.StatusBadRequest,
				Title:  "the CSR is unacceptable",
			},
		},
		{
			`errBadCSR with wrap`, args{err: errors.Wrap(store.ErrBadCSR, "invalid csr data")}, &common.ProblemDetail{
				Type:   "urn:ietf:params:acme:error:badCSR",
				Status: http.StatusBadRequest,
				Title:  "the CSR is unacceptable",
				Detail: "invalid csr data",
			},
		},
		{
			`manager: error`, args{err: store.ErrOrderNotReady}, &common.ProblemDetail{
				Type:   "urn:ietf:params:acme:error:orderNotReady",
				Status: http.StatusForbidden,
				Title:  `the request attempted to finalize an order that is not ready to be finalized`,
				Detail: ``,
			},
		},
		{
			`wrapped`, args{err: errors.Wrap(store.ErrIncorrectResponse, "hello")}, &common.ProblemDetail{
				Type:   "urn:ietf:params:acme:error:incorrectResponse",
				Status: http.StatusForbidden,
				Title:  `response received didn't match the challenge's requirements`,
				Detail: "hello",
			},
		},
		{
			`challenge response`, args{err: store.ErrIncorrectResponse}, &common.ProblemDetail{
				Type:   "urn:ietf:params:acme:error:incorrectResponse",
				Status: http.StatusForbidden,
				Title:  `response received didn't match the challenge's requirements`,
			},
		},
		{
			`challenge response: wrap`, args{err: errors.Wrap(store.ErrIncorrectResponse, "hello")}, &common.ProblemDetail{
				Type:   "urn:ietf:params:acme:error:incorrectResponse",
				Status: http.StatusForbidden,
				Title:  `response received didn't match the challenge's requirements`,
				Detail: "hello",
			},
		},
		{`success`, args{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			ts := newTestServer(ctx, t)
			ts.handler.(*helper.Echo).POST("/error", func(c echo.Context) error { return tt.args.err }, ts.server.errorHandler)

			resp, err := request.Post(ts.URL + "/error").Do(ctx)
			require.NoError(t, err)
			if tt.args.err == nil {
				return
			}

			got := &common.ProblemDetail{}
			defer resp.Body.Close()
			require.NoError(t, resp.JSON(got))

			require.Equal(t, common.MIMEProblemDetail, resp.Header.Get(echo.HeaderContentType))
			require.Regexp(t, `^urn:ietf:params:acme:error:`, got.Type)
			require.Equal(t, got.Status, resp.StatusCode, "status code mismatch")

			require.Equal(t, tt.wantProblem, got)
		})
	}
}
