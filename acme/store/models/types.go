package models

import (
	"database/sql/driver"
	"encoding/json"

	"github.com/pkg/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type Ident struct {
	Type  string `validate:"required,eq=dns"`
	Value string `validate:"required"`
}

type Identifier struct {
	Idents []Ident `validate:"required,dive"`
}

func NewIdentifier(idents []Ident) Identifier {
	return Identifier{Idents: idents}
}

func (ident *Identifier) GormDataType() string                                   { return "identifier" }
func (ident *Identifier) GormDBDataType(db *gorm.DB, field *schema.Field) string { return "text" }

func (ident *Identifier) Scan(in interface{}) error {
	var v []byte

	switch vv := in.(type) {
	case string:
		v = []byte(vv)
	case []byte:
		v = vv
	default:
		return errors.Errorf("fail to parse Identifier: %s", in)
	}

	if len(v) == 0 {
		return nil
	}

	if err := json.Unmarshal(v, &ident.Idents); err != nil {
		return err
	}

	return nil
}

func (ident Identifier) Value() (driver.Value, error) {
	if len(ident.Idents) == 0 {
		return "", nil
	}

	v, err := json.Marshal(&ident.Idents)
	if err != nil {
		return "", err
	}

	return string(v), nil
}
