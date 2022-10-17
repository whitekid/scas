package gormx

import (
	"database/sql/driver"
	"encoding/json"

	"github.com/pkg/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// Strings string list field type as json string list
type Strings []string

func (s *Strings) GormDataType() string                                   { return "strings" }
func (s *Strings) GormDBDataType(db *gorm.DB, field *schema.Field) string { return "text" }

func (s *Strings) Scan(in interface{}) error {
	var v []byte

	switch vv := in.(type) {
	case string:
		v = []byte(vv)
	case []byte:
		v = vv
	default:
		return errors.Errorf("fail to parse Strings: %s", in)
	}

	if len(v) == 0 {
		return nil
	}

	ss := []string{}
	if err := json.Unmarshal(v, &ss); err != nil {
		return err
	}
	*s = ss

	return nil
}

func (s Strings) Value() (driver.Value, error) {
	if len(s) == 0 {
		return "", nil
	}

	v, err := json.Marshal([]string(s))
	if err != nil {
		return "", err
	}

	return string(v), nil
}
