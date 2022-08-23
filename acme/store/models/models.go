package models

import (
	"time"

	"gorm.io/gorm"
)

func Migrate(db *gorm.DB) error {
	if err := db.AutoMigrate(&Nonce{}, &Account{}, &Order{}, &Identifier{}, &Authz{}, &Challenge{}, &Certificate{}); err != nil {
		return err
	}

	return nil
}

type Nonce struct {
	gorm.Model

	ID     string `gorm:"primaryKey,size:22"`
	Expire time.Time
}

type Account struct {
	gorm.Model

	ID                  string `gorm:"primaryKey,size:32"`
	Key                 string `gorm:"uniqueIndex,size:2048"`
	Status              string `gorm:"size:10"`
	Contacts            string `gorm:"size:200"` // TODO custom data type
	TermOfServiceAgreed bool
	TermAgreeAt         *time.Time

	Orders []Order `gorm:"foreignKey:AccountID"`
}

type Order struct {
	gorm.Model

	ID          string `gorm:"primaryKey,size:32"`
	AccountID   string
	Status      string `gorm:"size:100"`
	Expires     *time.Time
	Identifiers []Identifier `gorm:"foreignKey:OrderID"` // TODO JSON으로 하는건 어떨까? 귀찮다.
	NotBefore   *time.Time
	NotAfter    *time.Time
	Error       string       `gorm:"size:1000"` // common.ProblemDetail as json // TODO custom type
	Authz       []Authz      `gorm:"foreignKey:OrderID"`
	Certificate *Certificate `gorm:"foreignKey:OrderID"`
}

type Identifier struct {
	gorm.Model

	ID      string  `gorm:"primaryKey,size:32"`
	OrderID *string `gorm:"uniqueIndex:idx_identifier"`
	AuthzID *string `gorm:"uniqueIndex:idx_identifier"`

	Type  string `gorm:"uniqueIndex:idx_identifier;size:10"`
	Value string `gorm:"uniqueIndex:idx_identifier;size:256"`
}

type Authz struct {
	gorm.Model

	ID        string `gorm:"primaryKey;size=36"`
	AccountID string `gorm:"size=36"`
	OrderID   string `gorm:"size=36"`

	Status     string       `gorm:"not null;size:100"`
	Expires    *time.Time   `gorm:"not null"`
	Identifier Identifier   `gorm:"foreignKey:AuthzID"`
	Challenges []*Challenge `gorm:"foreignKey:AuthzID"`
	Wildcard   bool         `gorm:"default=false"`
}

type Challenge struct {
	gorm.Model

	ID         string `gorm:"primaryKey;size=36"`
	AuthzID    string `gorm:"size=36"`
	Type       string `gorm:"not null;size:100"`
	Token      string `gorm:"not null;size:200"`
	Status     string `gorm:"not null;size:100"`
	Validated  *time.Time
	Error      string `gorm:"size:1000"`
	RetryAfter *time.Time
}

type Certificate struct {
	gorm.Model

	ID      string `gorm:"primaryKey;size=36"`
	OrderID string `gorm:"size=36" validate:"required"`
	Chain   []byte `gorm:"not null" validate:"required"`
}
