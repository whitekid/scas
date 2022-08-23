package models

import (
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

func Migrate(db *gorm.DB) error {
	if err := db.AutoMigrate(&Project{}, &CAPool{}, &CertificateAuthority{}); err != nil {
		return errors.Wrap(err, "automirate failed")
	}

	if err := db.AutoMigrate(&Certificate{}); err != nil {
		return errors.Wrap(err, "automirate failed")
	}

	return nil
}
