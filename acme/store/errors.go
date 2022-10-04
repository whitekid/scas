package store

import (
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"scas/client/common"
)

var (
	ErrTermOfServiceChanged  = errors.New("terms of service have changed")
	ErrOrderNotFound         = NewACMEError(http.StatusNotFound, `unknown`, "order not found")
	ErrMultipleRecords       = errors.New("unexpected multiple records")
	ErrMethodNotAllowed      = NewACMEError(http.StatusMethodNotAllowed, `malformed`, `method not allowed`)
	ErrJOSEPayloadDecodeFail = NewACMEError(http.StatusBadRequest, `unknown`, `fail to decode jose payload`)
	ErrJOSEHeaderDecodeFail  = NewACMEError(http.StatusBadRequest, `unknown`, `fail to decode jose header`)
	ErrChallengeNotFound     = NewACMEError(http.StatusNotFound, `unknown`, "challenge not found")
	ErrCertNotFound          = NewACMEError(http.StatusNotFound, `unknown`, "certificate not found")
	ErrBadSignature          = NewACMEError(http.StatusForbidden, `unknown`, "badSignature")
	ErrBadChallengeStatus    = NewACMEError(http.StatusForbidden, `unknown`, "bad challenge status")
	ErrAuthzNotReady         = errors.New("invalid authorization status")
	ErrAuthzNotFound         = NewACMEError(http.StatusNotFound, `unknown`, `authz not found`)
	ErrAuthzExpired          = NewACMEError(http.StatusForbidden, `unknown`, `authorization expired`)
)

var (
	// acme error types; rfc8555 6.7
	// type example: "urn:ietf:params:acme:error:badCSR".
	ErrAccountDoesNotExist     = NewACMEError(http.StatusNotFound, "accountDoesNotExist", `the request specified an account that does not exist`)
	ErrAlreadyRevoked          = NewACMEError(http.StatusForbidden, "alreadyRevoked", `the request specified a certificate to be revoked that has already been revoked`)
	ErrBadCSR                  = NewACMEError(http.StatusBadRequest, "badCSR", `the CSR is unacceptable`)
	ErrBadNonce                = NewACMEError(http.StatusBadRequest, "badNonce", `the client sent an unacceptable anti-replay nonce`)
	ErrBadPublicKey            = NewACMEError(http.StatusBadRequest, "badPublicKey", `the JWS was signed by a public key the server does not support`)
	ErrBadRevocationReason     = NewACMEError(http.StatusBadRequest, "badRevocationReason", `the revocation reason provided is not allowed by the server`)
	ErrBadSignatureAlgorithm   = NewACMEError(http.StatusBadRequest, "badSignatureAlgorithm", `the JWS was signed with an algorithm the server does not support`)
	ErrCaa                     = NewACMEError(http.StatusForbidden, "caa", `certification Authority Authorization (CAA) records forbid the CA from issuing a certificate`)
	ErrCompound                = NewACMEError(http.StatusBadRequest, "compound", `specific error conditions are indicated in the "subproblems" array`)
	ErrConnection              = NewACMEError(http.StatusInternalServerError, "connection", `the server could not connect tovalidation target`)
	ErrDns                     = NewACMEError(http.StatusInternalServerError, "dns", `there was a problem with a DNS query during identifier validation`)
	ErrExternalAccountRequired = NewACMEError(http.StatusBadRequest, "externalAccountRequired", `the request must include a value for the "externalAccountBinding" field`)
	ErrIncorrectResponse       = NewACMEError(http.StatusForbidden, "incorrectResponse", `response received didn't match the challenge's requirements`)
	ErrInvalidContact          = NewACMEError(http.StatusBadRequest, "invalidContact", `a contact URL for an account was invalid`)
	ErrMalformed               = NewACMEError(http.StatusBadRequest, "malformed", `the request message was malformed`)
	ErrOrderNotReady           = NewACMEError(http.StatusForbidden, "orderNotReady", `the request attempted to finalize an order that is not ready to be finalized`)
	ErrRateLimited             = NewACMEError(http.StatusBadRequest, "rateLimited", `the request exceeds a rate limit`)
	ErrRejectedIdentifier      = NewACMEError(http.StatusForbidden, "rejectedIdentifier", `the server will not issue certificates for the identifier`)
	ErrServerInternal          = NewACMEError(http.StatusInternalServerError, "serverInternal", `the server experienced an internal error`)
	ErrTls                     = NewACMEError(http.StatusInternalServerError, "tls", `the server received a TLS error during validation`)
	ErrUnauthorized            = NewACMEError(http.StatusUnauthorized, "unauthorized", `the client lacks sufficient authorization`)
	ErrUnsupportedContact      = NewACMEError(http.StatusBadRequest, "unsupportedContact", `a contact URL for an account used an unsupported protocol scheme`)
	ErrUnsupportedIdentifier   = NewACMEError(http.StatusBadRequest, "unsupportedIdentifier", `an identifier is of an unsupported type`)
	ErrUserActionRequired      = NewACMEError(http.StatusForbidden, "userActionRequired", `visit the "instance" URL and take actions specified there`)
)

func NewACMEError(code int, errType, msg string) *common.ProblemDetail {
	return &common.ProblemDetail{
		Type:   "urn:ietf:params:acme:error:" + errType,
		Title:  msg,
		Status: code,
	}
}

func ErrToProblem(err error) *common.ProblemDetail {
	var p *common.ProblemDetail

	if !errors.As(err, &p) {
		return &common.ProblemDetail{
			Type:   ErrServerInternal.Type,
			Title:  ErrServerInternal.Title,
			Status: ErrServerInternal.Status,
			Detail: err.Error(),
		}
	}

	var e common.ProblemDetail = *p

	if cause := errors.Cause(err); cause != err {
		e.Detail = splitUnderlayingErrorMessage(err)
	}

	return &e
}

func splitUnderlayingErrorMessage(err error) string {
	msg := err.Error()
	i := strings.LastIndex(msg, ": ")
	if i == -1 {
		return msg
	}

	return msg[:i]
}
