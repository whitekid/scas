package models

import (
	"time"

	"gorm.io/gorm"

	"scas/pkg/helper/gormx"
)

type Project struct {
	gorm.Model

	ID   string `gorm:"primaryKey;size:22;check:id <> ''"`
	Name string `gorm:"not null;size:256:check:name<>''" validate:"required"`
}

func (p *Project) BeforeCreate(tx *gorm.DB) error {
	gormx.GenerateID(&p.ID)

	return nil
}

type CAPool struct {
	gorm.Model

	ID        string `gorm:"primaryKey;size:22;check:id<>''"`
	Name      string `gorm:"not null;uniqueIndex:capool_idx_name;size:256;check:name<>''" validate:"required"`
	ProjectID string `gorm:"not null;uniqueIndex:capool_idx_name;size:22;check:project_id<>''" validate:"required"`
	Project   *Project
}

func (p *CAPool) BeforeCreate(tx *gorm.DB) error {
	gormx.GenerateID(&p.ID)

	return nil
}

// TODO certificate와 비슷한데, 통합?
type CertificateAuthority struct {
	gorm.Model

	ID                   string                `gorm:"primaryKey;size:22;check:id<>''"`
	ProjectID            string                `gorm:"not null;size:22;check:project_id<>''" validate:"required"`
	Project              *Project              `gorm:"foreignKey:ProjectID"`
	CAPoolID             string                `gorm:"not null;size:22;check:ca_pool_id<>''" validate:"required"`
	CAPool               *CAPool               `gorm:"foreignKey:CAPoolID"`
	CAID                 *string               `gorm:"size:22"` // parent CAID, if nil it's root CA
	CertificateAuthority *CertificateAuthority `gorm:"foreignKey:CAID"`
	Status               string                `gorm:"not null;size:20" validate:"required"`

	Request []byte // json encoded request
	Cert    []byte
	Key     []byte
}

func (a *CertificateAuthority) BeforeCreate(tx *gorm.DB) error {
	gormx.GenerateID(&a.ID)

	return nil
}

type Certificate struct {
	gorm.Model

	ID                   string                `gorm:"primaryKey;size:22;check:id<>''"`
	ProjectID            string                `gorm:"not null;size:22;check:project_id<>''" validate:"required"`
	Project              *Project              `gorm:"foreignKey:ProjectID"`
	CAPoolID             string                `gorm:"not null;size:22;check:ca_pool_id<>''" validate:"required"`
	CAPool               *CAPool               `gorm:"foreignKey:CAPoolID"`
	CAID                 string                `gorm:"not null;size:22;check:ca_id<>''"`
	CertificateAuthority *CertificateAuthority `gorm:"foreignKey:CAID"`

	Request []byte // json encoded request
	Cert    []byte
	Key     []byte
	Chain   []byte

	Status        string `gorm:"not null;size:20" validate:"required"`
	RevokedAt     *time.Time
	RevokedReason string `gorm:"size:20"`

	// for search
	CN string `gorm:"size:256"`
}

func (c *Certificate) BeforeCreate(tx *gorm.DB) error {
	gormx.GenerateID(&c.ID)

	return nil
}
