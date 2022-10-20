package helper

import (
	"github.com/go-playground/validator/v10"
	"github.com/pkg/errors"
)

var validate = validator.New()

// Validate shortcuts
func ValidateStruct(s interface{}) error              { return validate.Struct(s) }
func ValidateVar(field interface{}, tag string) error { return validate.Var(field, tag) }

func ValidateVars(vars ...interface{}) error {
	for i := 0; i < len(vars); i += 2 {
		if err := ValidateVar(vars[i], (vars[i+1]).(string)); err != nil {
			return err
		}
	}
	return nil
}

func IsValidationError(err error) bool {
	var verr *validator.ValidationErrors

	return errors.As(err, &verr)
}
