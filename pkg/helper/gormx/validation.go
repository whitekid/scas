package gormx

import (
	"reflect"

	"gorm.io/gorm"

	"scas/pkg/helper"
)

type validationImpl struct{}

func NewValidationPlugin() gorm.Plugin { return &validationImpl{} }

func (v *validationImpl) Name() string { return "validation" }
func (v *validationImpl) Initialize(db *gorm.DB) error {
	callback := db.Callback()
	if callback.Create().Get("validations:validation") == nil {
		callback.Create().Before("gorm:before_create").Register("validations:validate", v.validate)
	}

	if callback.Update().Get("validations:validate") == nil {
		callback.Update().Before("gorm:before_update").Register("validations:validate", v.validate)
	}

	return nil
}

func (v *validationImpl) validate(db *gorm.DB) {
	if db.Statement.Model != nil {
		switch reflect.TypeOf(db.Statement.Model).Kind() {
		case reflect.Struct, reflect.Pointer:
			db.Error = helper.ValidateStruct(db.Statement.Model)
		}
	}
}
