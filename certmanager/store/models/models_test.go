package models

import (
	"testing"

	"scas/pkg/helper/gormx"
	"scas/pkg/testutils"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

func newFixture(t *testing.T, dbURL string) *fixture {
	db := testutils.Must1(gormx.Open(dbURL, &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix: "scas_",
		},
	}))
	require.NoError(t, Migrate(db))

	proj := &Project{Name: "test project"}
	require.NoError(t, db.Create(proj).Error)

	pool := &CAPool{Name: "test capool", ProjectID: proj.ID}
	require.NoError(t, db.Create(pool).Error)

	ca := &CertificateAuthority{
		ProjectID: proj.ID,
		CAPoolID:  pool.ID,
		Status:    "active",
	}
	require.NoError(t, db.Create(ca).Error)

	return &fixture{
		DB:   db,
		proj: proj,
		pool: pool,
		ca:   ca,
	}
}

type fixture struct {
	*gorm.DB
	proj *Project
	pool *CAPool
	ca   *CertificateAuthority
}

func TestProject(t *testing.T) {
	testutils.ForEachSQLDriver(t, func(t *testing.T, dbURL string, reset func()) {
		fixture := newFixture(t, dbURL)

		proj := &Project{
			Name: "test",
		}
		require.NoError(t, fixture.Create(proj).Error)

		var got Project
		require.NoError(t, fixture.First(&got, "id = ?", proj.ID).Error)
	})
}

func TestCAPool(t *testing.T) {
	testutils.ForEachSQLDriver(t, func(t *testing.T, dbURL string, reset func()) {
		fixture := newFixture(t, dbURL)

		pool := &CAPool{Name: "pool", ProjectID: fixture.proj.ID}
		require.NoError(t, fixture.Create(pool).Error)

		var got CAPool
		require.NoError(t, fixture.First(&got, "id = ?", pool.ID).Error)
	})
}

func TestCertificateAuthority(t *testing.T) {
	testutils.ForEachSQLDriver(t, func(t *testing.T, dbURL string, reset func()) {
		fixture := newFixture(t, dbURL)

		ca := &CertificateAuthority{
			ProjectID: fixture.proj.ID,
			CAPoolID:  fixture.pool.ID,
			Status:    "valid",
		}
		require.NoError(t, fixture.Create(ca).Error)

		var got CertificateAuthority
		require.NoError(t, fixture.First(&got, "id = ?", ca.ID).Error)
	})
}

func TestCertificate(t *testing.T) {
	testutils.ForEachSQLDriver(t, func(t *testing.T, dbURL string, reset func()) {
		fixture := newFixture(t, dbURL)

		cert := &Certificate{
			ProjectID: fixture.proj.ID,
			CAPoolID:  fixture.pool.ID,
			CAID:      fixture.ca.ID,
			Status:    "valid",
		}
		require.NoError(t, fixture.Create(cert).Error)

		var got Certificate
		require.NoError(t, fixture.First(&got, "id = ?", cert.ID).Error)
	})
}
