package store

import (
	"context"
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
	testProjectName = "project 1"
	testPoolName    = "pool 1"
)

func newSQL(ctx context.Context, t *testing.T, dburl string) *testSQL {
	s := testSQL{sqlStoreImpl: NewSQL(dburl).(*sqlStoreImpl)}

	project := testutils.Must1(s.createProject(ctx, testProjectName))
	caPool := testutils.Must1(s.createCAPool(ctx, project.ID, testPoolName))
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
			testutils.ForEachSQLDriver(t, func(t *testing.T, dburl string, resetFixture func()) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				resetFixture()
				s := newSQL(ctx, t, dburl)

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
		})
	}
}

func Test_sqlStoreImpl_CreateCAPool(t *testing.T) {
	testutils.ForEachSQLDriver(t, func(t *testing.T, dburl string, resetFixture func()) {
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

				resetFixture()
				s := newSQL(ctx, t, dburl)

				projectID := fx.Ternary(tt.args.projectID == "", s.projectID, tt.args.projectID)

				_, err := s.CreateCAPool(ctx, projectID, tt.args.caPoolName)
				if (err != nil) != tt.wantErr {
					t.Errorf("sqlStoreImpl.CreateCAPool() error = %v, wantErr %+v", err, tt.wantErr)
					return
				}
				require.ErrorIs(t, err, tt.targetErr)
			})
		}
	})
}
