package models

import (
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

func Migrate(db *gorm.DB) error {
	models := [][]interface{}{
		{&Project{}, &CertificateAuthority{}},
		{&Certificate{}},
	}

	for _, m := range models {
		if err := autoMigate(db, m...); err != nil {
			return err
		}

	}

	return nil
}

func autoMigate(db *gorm.DB, m ...any) error {
	if err := db.AutoMigrate(m...); err != nil {
		return errors.Wrap(err, "automirate failed")
	}
	return nil
}
