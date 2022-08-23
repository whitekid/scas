package helper

import (
	"github.com/go-playground/validator/v10"
	"github.com/pkg/errors"
)

var validate = validator.New()

// Validate shortcuts
func ValidateStruct(s interface{}) error              { return validate.Struct(s) }
func ValidateVar(field interface{}, tag string) error { return validate.Var(field, tag) }

func IsValidationError(err error) bool {
	var verr *validator.ValidationErrors

	return errors.As(err, &verr)
}
