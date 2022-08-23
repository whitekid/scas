package models

import (
	"time"

	"gorm.io/gorm"
)

type Project struct {
	gorm.Model

	ID   string `gorm:"primaryKey;size:37"`
	Name string `gorm:"size:256"`
}

type CAPool struct {
	gorm.Model

	ID        string `gorm:"primaryKey;size:37"`
	Name      string `gorm:"uniqueIndex:idx_name;size:256"`
	ProjectID string `gorm:"uniqueIndex:idx_name;size:37"`
	Project   Project
}

// TODO certificate와 비슷한데, 통합?
type CertificateAuthority struct {
	gorm.Model

	ID                   string                `gorm:"primaryKey;size:37"`
	ProjectID            string                `gorm:"size:37"`
	Project              Project               `gorm:"foreignKey:ProjectID"`
	CAPoolID             string                `gorm:"size:37"`
	CAPool               CAPool                `gorm:"foreignKey:CAPoolID"`
	CAID                 *string               `gorm:"size:37"` // parent CAID, if nil it's root CA
	CertificateAuthority *CertificateAuthority `gorm:"foreignKey:CAID"`
	Status               string

	Request []byte // json encoded request
	Cert    []byte
	Key     []byte
}

type Certificate struct {
	gorm.Model

	ID                   string                `gorm:"primaryKey;size37"`
	ProjectID            string                `gorm:"size:37"`
	Project              Project               `gorm:"foreignKey:ProjectID"`
	CAPoolID             string                `gorm:"size:37"`
	CAPool               CAPool                `gorm:"foreignKey:CAPoolID"`
	CAID                 string                `gorm:"size:37"`
	CertificateAuthority *CertificateAuthority `gorm:"foreignKey:CAID"`

	Request []byte // json encoded request
	Cert    []byte
	Key     []byte
	Chain   []byte

	Status        string `gorm:"size:10"`
	RevokedAt     *time.Time
	RevokedReason string `gorm:"size:37"`

	// for search
	CN string `gorm:"size:256"`
}
