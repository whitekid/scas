package testutils

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
)

type TestChallengeServer struct {
	*httptest.Server
	Port string
}

func NewChallengeServer(ctx context.Context, token string, thumbprint []byte) *TestChallengeServer {
	challengeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !strings.HasPrefix(req.URL.Path, "/.well-known/acme-challenge/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		parts := strings.Split(req.URL.Path, "/")
		reqToken := parts[len(parts)-1] // challenge token

		if token == reqToken {
			w.Header().Set(echo.HeaderContentType, "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			out := fmt.Sprintf("%s.%s", token, base64.RawURLEncoding.EncodeToString(thumbprint))
			w.Write([]byte(out))
		}

		w.WriteHeader(http.StatusNotFound)
	}))

	u, _ := url.Parse(challengeServer.URL)

	go func() {
		<-ctx.Done()
		challengeServer.Close()
	}()

	return &TestChallengeServer{
		Server: challengeServer,
		Port:   u.Port(),
	}
}
