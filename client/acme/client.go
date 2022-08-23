package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/log"
	"github.com/whitekid/goxp/request"

	"scas/client/common"
	"scas/pkg/helper/x509x"
)

const (
	headerLocation = "Location"
)

// Client represents ACME client
//
// TODO integreated with scas client
// TODO JWS authentication using account's private key
// TODO error handling
type Client struct {
	endpoint  string
	directory Directory
	nonce     string
	client    *http.Client

	account *Account // current account
	key     x509x.PrivateKey
	pub     []byte // private, pub key pair in DER format
}

func New(endpoint string, key []byte) (*Client, error) {
	return WithClient(endpoint, key, nil)
}

func WithClient(endpoint string, key []byte, client *http.Client) (*Client, error) {
	var priv x509x.PrivateKey
	var err error

	if key == nil {
		// Server MUST implement ES256(ECDSA256) and SHOULD implement EdDSA(Ed25519)
		// TODO Ed25519 supports
		priv, err = x509x.GenerateKey(x509.ECDSAWithSHA256)
		if err != nil {
			return nil, errors.Wrapf(err, "fail to generate key")
		}
	} else {
		priv, err = x509x.ParsePrivateKey(key)
		if err != nil {
			return nil, errors.Wrapf(err, "fail to parse private key")
		}
	}

	derBytes, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, errors.Wrapf(err, "fail to get public key")
	}

	c := &Client{
		endpoint: endpoint,
		client:   client,
		key:      priv,
		pub:      derBytes,
	}

	ctx := context.Background()
	if err := c.getDirectory(ctx); err != nil {
		return nil, errors.Wrapf(err, "fail to create client")
	}

	if err := c.newNonce(ctx); err != nil {
		return nil, errors.Wrapf(err, "fail to create client")
	}

	return c, nil
}

// Thumbprint returns thumbprint of public key
func (c *Client) Thumbprint() []byte { return crypto.SHA256.New().Sum(c.pub) }

type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	NewAuthz   string `json:"newAuthz"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`

	TermOfService           string   `json:"termOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CAAIdentities           []string `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool     `json:"externalAccountRequired,omitempty"`
}

const HeaderReplayNonce = "Replay-Nonce"

func (c *Client) sendRequest(ctx context.Context, req *request.Request) (*request.Response, error) {
	// TODO: client: ignore invalid reply-nonce values
	resp, err := req.Do(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "request failed")
	}

	if !resp.Success() {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrap(err, "body read failed")
		}

		problem := &common.ProblemDetail{}
		if err := json.Unmarshal(body, problem); err != nil {
			return nil, errors.Wrap(err, "problem decode failed")
		}

		return nil, problem
	}

	return resp, nil
}

type JOSERequest struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type JOSEHeader struct {
	Algorithm string `json:"alg" validate:"required"` // ES256(ECDSA256), EdDSA(Ed25519)
	JWK       string `json:"jwk,omitempty"`           // json web key, public key
	KID       string `json:"kid,omitempty"`           // account URL
	Nonce     string `json:"nonce"`
	URL       string `json:"url"  validate:"required"`
}

// TODO Ed25519 supports
func keyToAlgorithm(priv x509x.PrivateKey) string {
	switch priv.(type) {
	case *ecdsa.PrivateKey:
		return "ES256"
	default:
		log.Fatalf("unsupported algorithm: %T", priv)
		return ""
	}
}

func (c *Client) newJOSERequest(url string, payload interface{}, priv x509x.PrivateKey, pub []byte) (*JOSERequest, error) {
	req := &JOSERequest{}

	if payload != nil {
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, errors.Wrapf(err, "fail to make jose request")
		}
		req.Payload = base64.RawURLEncoding.EncodeToString(payloadBytes)
	}

	header := &JOSEHeader{
		Algorithm: keyToAlgorithm(c.key),
		Nonce:     c.nonce,
		URL:       url,
	}

	if pub == nil {
		if c.account == nil {
			header.JWK = base64.RawURLEncoding.EncodeToString(c.pub)
		} else {
			header.KID = c.account.Location
		}
	} else {
		header.JWK = base64.RawURLEncoding.EncodeToString(pub)
	}

	protected, err := json.Marshal(header)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to make jose request")
	}
	req.Protected = base64.RawURLEncoding.EncodeToString(protected)

	signature, err := priv.Sign(rand.Reader, crypto.SHA256.New().Sum([]byte(fmt.Sprintf("%s.%s", req.Protected, req.Payload))), nil)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to sign payload")
	}

	req.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return req, nil
}

func (c *Client) sendJOSERequest(ctx context.Context, method string, url string, payload interface{}) (*request.Response, error) {
	req, err := c.newJOSERequest(url, payload, c.key, c.pub)
	if err != nil {
		return nil, err
	}

	return c.sendRequest(ctx, request.New(method, url).ContentType("application/jose+json").JSON(req))
}

func (c *Client) getDirectory(ctx context.Context) error {
	resp, err := c.sendRequest(ctx, request.Get("%s/directory", c.endpoint))
	if err != nil {
		return errors.Wrapf(err, "fail to get directory")
	}
	defer resp.Body.Close()

	if err := resp.JSON(&c.directory); err != nil {
		return errors.Wrap(err, "fail to get directory")
	}

	log.Debugf("directory: %+v", c.directory)

	return nil
}

func (c *Client) newNonce(ctx context.Context) error {
	resp, err := c.sendRequest(ctx, request.Head(c.directory.NewNonce))
	if err != nil {
		return errors.Wrapf(err, "fail to acquire new nonce")
	}

	c.nonce = resp.Header.Get(HeaderReplayNonce)
	if c.nonce == "" {
		return errors.New("empty nonce")
	}

	return nil
}

func (c *Client) Nonce() string { return c.nonce }

// OrderList
// Example
//
//	  {
//		"orders": [
//		  "https://example.com/acme/order/TOlocE8rfgo",
//		  "https://example.com/acme/order/4E16bbL5iSw",
//		  /* more URLs not shown for example brevity */
//		  "https://example.com/acme/order/neBHYLfw0mg"
//		]
//	  }
type OrderList struct {
	Orders []string `json:"orders"`
}

// Authorization represents server authorization for an account
// Example
// 	 {
//      "status": "valid",
//      "expires": "2015-03-01T14:09:07.99Z",
//     "identifier": {
//     "type": "dns",
//     "value": "www.example.org"
//   },
//   "challenges": [
//     {
//       url": "https://example.com/acme/chall/prV_B7yEyA4",
//       "type": "http-01",
//       "status": "valid",
//       "token": "DGyRejmCefe7v4NfDGDKfA",
//       "validated": "2014-12-01T12:05:58.16Z"
//     }
//   ],
// 	 "wildcard": false
//   }
