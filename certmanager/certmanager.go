package certmanager

import (
	"gorm.io/gorm"

	"scas/certmanager/provider"
	"scas/certmanager/repository"
	"scas/certmanager/store"
	"scas/certmanager/types"
	"scas/pkg/helper/gormx"
)

type (
	Interface = repository.Interface
	Provider  = provider.Interface
	Store     = store.Interface

	Certificate = types.Certificate

	CreateRequest = provider.CreateRequest

	ProjectListOpt     = store.ProjectListOpt
	CertificateListOpt = store.CertificateListOpt
)

var (
	ErrUniqueConstraintFailed     = gormx.ErrUniqueConstraintFailed
	ErrForeignKeyConstraintFailed = gormx.ErrForeignKeyConstraintFailed
	ErrRecordNotFound             = gorm.ErrRecordNotFound
	ErrMultipleRecord             = store.ErrMultipleRecord
	ErrInvalidStatus              = store.ErrInvalidStatus
)

func New(provider Provider, store Store) Interface {
	return repository.New(provider, store)
}

func NativeProvider() Provider    { return provider.Native() }
func SQLStore(dburl string) Store { return store.NewSQL(dburl) }
