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

	ca := &CertificateAuthority{
		ProjectID: proj.ID,
		Status:    "active",
	}
	require.NoError(t, db.Create(ca).Error)

	return &fixture{
		DB:   db,
		proj: proj,
		ca:   ca,
	}
}

type fixture struct {
	*gorm.DB
	proj *Project
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

func TestCertificateAuthority(t *testing.T) {
	testutils.ForEachSQLDriver(t, func(t *testing.T, dbURL string, reset func()) {
		fixture := newFixture(t, dbURL)

		ca := &CertificateAuthority{
			ProjectID: fixture.proj.ID,
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
			CAID:      fixture.ca.ID,
			Status:    "valid",
		}
		require.NoError(t, fixture.Create(cert).Error)

		var got Certificate
		require.NoError(t, fixture.First(&got, "id = ?", cert.ID).Error)
	})
}
