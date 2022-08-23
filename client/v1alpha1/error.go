package v1alpha1

import "fmt"

func NewHTTPError(code int, msg string, args ...interface{}) error {
	return &HttpError{code: code, msg: fmt.Sprintf(msg, args...)}
}

type HttpError struct {
	code int
	msg  string
}

func (e *HttpError) Error() string { return e.msg }
func (e *HttpError) Code() int     { return e.code }
