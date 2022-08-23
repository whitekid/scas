package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	"scas/certmanager/provider"
	"scas/certmanager/store/models"
	"scas/client/common"
	"scas/client/common/x509types"
	"scas/pkg/helper"
	"scas/pkg/helper/gormx"
	"scas/pkg/testutils"
)

type testSQL struct {
	*sqlStoreImpl

	projectID string
	caPoolID  string
}

func (s *testSQL) updateStatus(ctx context.Context, projectID string, caPoolID string, certID string, status common.Status) error {
	log.Debugf("updateStatus(): project=%s, capool=%s, cert=%s", projectID, caPoolID, certID)

	cert, err := s.getCertificate(ctx, projectID, caPoolID, certID)
	if err != nil {
		return errors.Wrap(err, "fail to update certificate status")
	}

	cert.Status = status.String()
	cert.RevokedAt = helper.NowP()
	if tx := s.db.Save(cert); tx.Error != nil {
		return errors.Wrap(err, "fail to update certificate status")
	}

	return nil
}

const (
	testProjectID   = "project-id"
	testProjectName = "project 1"
	testPoolID      = "pool id"
	testPoolName    = "pool 1"
)

func newSQL(ctx context.Context, t *testing.T, scheme string) *testSQL {
	dbname := testutils.DBName(t)
	var dburl string

	switch scheme {
	case "sqlite":
		os.Remove(dbname + ".db")
		dburl = fmt.Sprintf("sqlite://%s.db", dbname)

	case "mysql":
		db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/mysql")
		require.NoError(t, err)
		defer db.Close()

		db.Exec("DROP DATABASE " + dbname)
		_, err = db.Exec("CREATE DATABASE " + dbname)
		require.NoError(t, err)

		dburl = fmt.Sprintf("mysql://root:@127.0.0.1:3306/%s?parseTime=true", dbname)

	case "pgsql":
		db, err := sql.Open("pgx", "dbname=postgres")
		require.NoError(t, err)
		defer db.Close()

		db.Exec("DROP DATABASE " + dbname)
		_, err = db.Exec("CREATE DATABASE " + dbname)
		require.NoError(t, err)

		dburl = fmt.Sprintf("postgresql:///%s", dbname)

	default:
		require.Failf(t, "not supported scheme", scheme)
	}

	s := testSQL{sqlStoreImpl: NewSQL(dburl).(*sqlStoreImpl)}

	project := testutils.Must1(s.createProject(ctx, testProjectID, testProjectName))
	caPool := testutils.Must1(s.createCAPool(ctx, project.ID, testPoolID, testPoolName))
	rootCA := testutils.Must1(s.CreateCA(ctx, project.ID, caPool.ID, nil, nil, nil, nil))
	subCA := testutils.Must1(s.CreateCA(ctx, project.ID, caPool.ID, nil, nil, nil, &rootCA.ID))
	testutils.Must1(s.CreateCertificate(ctx, project.ID, caPool.ID, &provider.CreateRequest{
		CommonName:   "server.example.com",
		KeyAlgorithm: x509types.ECDSA_P384,
		NotAfter:     helper.AfterNow(1, 0, 0),
		NotBefore:    helper.AfterNow(0, -1, 0),
	}, nil, nil, nil, subCA.ID))

	cert := testutils.Must1(s.CreateCertificate(ctx, project.ID, caPool.ID, &provider.CreateRequest{
		CommonName:   "invalid.example.com",
		KeyAlgorithm: x509types.ECDSA_P256,
		NotAfter:     helper.AfterNow(1, 0, 0),
		NotBefore:    helper.AfterNow(0, -1, 0),
	}, nil, nil, nil, subCA.ID))
	require.NoError(t, s.updateStatus(ctx, cert.ProjectID, cert.CAPoolID, cert.ID, common.StatusSuspended))

	s.projectID, s.caPoolID = project.ID, caPool.ID
	return &s
}

func Test_sqlStoreImpl_listCertificate(t *testing.T) {
	type args struct {
		opts CertificateListOpt
	}
	tests := []struct {
		name    string
		args    args
		wantLen int
		wantErr bool
	}{
		{"status", args{opts: CertificateListOpt{Status: common.StatusActive}}, 1, false},
		{"all status", args{opts: CertificateListOpt{}}, 2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			s := newSQL(ctx, t, "sqlite")

			got, err := s.listCertificate(ctx, s.projectID, s.caPoolID, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("sqlStoreImpl.listCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			require.Equal(t, tt.wantLen, len(got))

			if tt.args.opts.Status != common.StatusNone {
				certs := fx.Filter(got, func(x *models.Certificate) bool { return x.Status != tt.args.opts.Status.String() })
				require.Equal(t, 0, len(certs))
			}
		})
	}
}

func forEachDriver(t *testing.T, testfn func(t *testing.T, driver string)) {
	fx.ForEach([]string{"sqlite", "mysql", "pgsql"}, func(_ int, driver string) { forOneDriver(t, driver, testfn) })
}

func forOneDriver(t *testing.T, driver string, testfn func(t *testing.T, driver string)) {
	t.Run(driver, func(t *testing.T) {
		if os.Getenv("SCAS_SKIP_SQL_"+strings.ToUpper(driver)) == "true" {
			t.Skip("skip driver " + driver)
			return
		}

		testfn(t, driver)
	})
}

// FIXME 영 맘에 안드네...
func Test_sqlStoreImpl_CreateCAPool(t *testing.T) {
	forEachDriver(t, test_sqlStoreImpl_CreateCAPool)
}

func test_sqlStoreImpl_CreateCAPool(t *testing.T, driver string) {
	type args struct {
		projectID  string
		caPoolName string
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		targetErr error
	}{
		{"duplicate name", args{"", testPoolName}, true, gormx.ErrUniqueConstraintFailed},
		{"invalid project id", args{"invalid-project", "pool-x"}, true, gormx.ErrForeignKeyConstraintFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			s := newSQL(ctx, t, driver)

			projectID := fx.Ternary(tt.args.projectID == "", s.projectID, tt.args.projectID)

			_, err := s.CreateCAPool(ctx, projectID, tt.args.caPoolName)
			if (err != nil) != tt.wantErr {
				t.Errorf("sqlStoreImpl.CreateCAPool() error = %v, wantErr %+v", err, tt.wantErr)
				return
			}
			require.ErrorIs(t, err, tt.targetErr)
		})
	}
}
