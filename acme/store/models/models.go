package models

import (
	"encoding/hex"
	"time"

	"gorm.io/gorm"

	"scas/pkg/helper"
)

func Migrate(db *gorm.DB) error {
	if err := db.AutoMigrate(&Project{}, &Term{}, &Nonce{}, &Account{}, &Order{}, &Authz{}, &Challenge{}, &Certificate{}); err != nil {
		return err
	}

	return nil
}

type Project struct {
	gorm.Model

	ID   string `gorm:"primaryKey;size:22;check:id <> ''"`
	Name string `gorm:"not null" validate:"required"`

	TermOfService string     // TODO
	TermUpdatedAt *time.Time // TODO
	TermID        *string    // Current Term ID
	Term          *Term

	Website                 string  `gorm:"size:255"`
	CAAIdentities           Strings `gorm:"size:255"` // rfc6844 Certification Authority Authorization(CAA)
	ExternalAccountRequired bool

	Terms        []Term        `gorm:"foreignKey:ProjectID"`
	Nonces       []Nonce       `gorm:"foreignKey:ProjectID"`
	Accounts     []Account     `gorm:"foreignKey:ProjectID"`
	Orders       []Order       `gorm:"foreignKey:ProjectID"`
	Authzs       []Authz       `gorm:"foreignKey:ProjectID"`
	Challenges   []Challenge   `gorm:"foreignKey:ProjectID"`
	Certificates []Certificate `gorm:"foreignKey:ProjectID"`
}

func (p *Project) BeforeCreate(tx *gorm.DB) error {
	genID(&p.ID)

	return nil
}

// Term term of service
type Term struct {
	gorm.Model

	ID        string `gorm:"primaryKey;size:22;uniqueIndex:idx_term_proj_id;check:project_id<>'';check:id<>''"`
	ProjectID string `gorm:"not null;size:22;uniqueIndex:idx_term_proj_id;check:project_id<>''" validate:"required"`
	Content   string `gorm:"type:text;check:content<>''" validate:"required"`
}

func (t *Term) BeforeCreate(tx *gorm.DB) error {
	genID(&t.ID)

	return nil
}

type Nonce struct {
	gorm.Model

	ProjectID string `gorm:"not null;size:22;uniqueIndex:idx_nonce_proj_id;check:project_id<>''" validate:"required"`
	ID        string `gorm:"primaryKey;size:22;uniqueIndex:idx_nonce_proj_id;check:id <> ''"`
	Expire    time.Time
}

func (n *Nonce) BeforeCreate(tx *gorm.DB) error { return genID(&n.ID) }

type Account struct {
	gorm.Model

	ID                  string  `gorm:"primaryKey;not null;size:32;uniqueIndex:idx_acct_proj_id;check:id <> ''"`
	ProjectID           string  `gorm:"not null;size:22;uniqueIndex:idx_acct_proj_id;check:project_id<>''" validate:"required"`
	Key                 string  `gorm:"uniqueIndex;size:2048" validate:"required"`
	Status              string  `gorm:"size:10" validate:"required"`
	Contacts            Strings `gorm:"size:250;not null;check:contacts <> ''" validate:"required"`
	TermOfServiceAgreed bool
	TermAgreeAt         *time.Time

	Orders []Order `gorm:"foreignKey:AccountID"`
}

func (acct *Account) BeforeCreate(tx *gorm.DB) error { return genID(&acct.ID) }

type Order struct {
	gorm.Model

	ID          string `gorm:"primaryKey;size:32;uniqueIndex:idx_order_proj_id;check:id <> ''"`
	ProjectID   string `gorm:"not null;size:22;uniqueIndex:idx_order_proj_id;check:project_id<>''" validate:"required"`
	AccountID   string `validate:"required"`
	Status      string `gorm:"size:100" validate:"required"`
	Expires     *time.Time
	Identifiers Identifier   `validate:"required,dive"`
	NotBefore   *time.Time   `validate:"required"`
	NotAfter    *time.Time   `validate:"required"`
	Error       string       `gorm:"size:1000"` // common.ProblemDetail as json // TODO custom type
	Authz       []Authz      `gorm:"foreignKey:OrderID"`
	Certificate *Certificate `gorm:"foreignKey:OrderID"`
}

func (o *Order) BeforeCreate(tx *gorm.DB) error { return genID(&o.ID) }

type Authz struct {
	gorm.Model

	ID        string `gorm:"primaryKey;size=36;uniqueIndex:idx_authz_proj_id;check:id <> ''"`
	ProjectID string `gorm:"not null;size:22;uniqueIndex:idx_authz_proj_id;check:project_id<>''" validate:"required"`
	AccountID string `gorm:"size=36" validate:"required"`
	OrderID   string `gorm:"size=36" validate:"required"`

	Status     string       `gorm:"not null;size:100" validate:"required"`
	Expires    *time.Time   `gorm:"not null" validate:"required"`
	Identifier Identifier   `validate:"required,dive"`
	Challenges []*Challenge `gorm:"foreignKey:AuthzID"`
	Wildcard   bool         `gorm:"default=false"`
}

func (a *Authz) BeforeCreate(tx *gorm.DB) error { return genID(&a.ID) }

type Challenge struct {
	gorm.Model

	ID         string `gorm:"primaryKey;size=36;uniqueIndex:idx_challenge_proj_id;check:id <> ''"`
	ProjectID  string `gorm:"not null;size:22;uniqueIndex:idx_challenge_proj_id;check:project_id<>''" validate:"required"`
	AuthzID    string `gorm:"size=36" validate:"required"`
	Type       string `gorm:"not null;size:100" validate:"required"`
	Token      string `gorm:"not null;size:200"`
	Status     string `gorm:"not null;size:100" validate:"required"`
	Validated  *time.Time
	Error      string `gorm:"size:1000"`
	RetryAfter *time.Time
}

func (ch *Challenge) BeforeCreate(tx *gorm.DB) error {
	genID(&ch.ID)
	genID(&ch.Token)
	return nil
}

type Certificate struct {
	gorm.Model

	ID           string `gorm:"primaryKey;size=36;uniqueIndex:idx_cert_proj_id;check:id <> ''"`
	ProjectID    string `gorm:"not null;size:22;uniqueIndex:idx_cert_proj_id;check:project_id<>''" validate:"required"`
	OrderID      string `gorm:"size=36" validate:"required"`
	Chain        []byte `gorm:"not null" validate:"required"` // certificate chain as PEM format
	Hash         string `gorm:"not null"`                     // sha256sum of certificate
	RevokeReason string `gorm:"size=64"`
	RevokedAt    *time.Time
}

func (cert *Certificate) BeforeCreate(tx *gorm.DB) error {
	genID(&cert.ID)
	cert.Hash = hex.EncodeToString(helper.SHA256Sum(cert.Chain))

	return nil
}
