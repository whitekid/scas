package testutils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"

	"scas/pkg/helper"
)

// TODO need to refactor with TestTLSServer
func TestTLSServerWithCRLVerifify(ctx context.Context, crt, key, chainCrt []byte, serverName string, wantCode int) error {
	cert, err := tls.X509KeyPair(crt, key)
	if err != nil {
		return err
	}

	// server
	ts := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	ln = tls.NewListener(ln, ts)
	go func() {
		handler := http.NewServeMux()
		handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "hello") })
		http.Serve(ln, handler)
	}()

	// client
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(chainCrt)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:               caPool,
				VerifyPeerCertificate: helper.NewCRLVerifier().Verify,
			},
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/", serverName, ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		return err
	}

	if resp.StatusCode != wantCode {
		return fmt.Errorf("want %d but get status %d", wantCode, resp.StatusCode)
	}

	return nil
}

func TestTLSServer(ctx context.Context, crt, key, chainCrt []byte, serverName string, wantCode int) error {
	cert, err := tls.X509KeyPair(crt, key)
	if err != nil {
		return err
	}
	_ = cert

	ts := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	ln = tls.NewListener(ln, ts)
	go func() {
		handler := http.NewServeMux()
		handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "hello") })
		http.Serve(ln, handler)
	}()

	// client
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(chainCrt)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://%s:%d/", serverName, ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		return err
	}

	if resp.StatusCode != wantCode {
		return fmt.Errorf("want %d but get status %d", wantCode, resp.StatusCode)
	}

	return nil
}
