package store

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	"scas/certmanager/provider"
	"scas/certmanager/store/models"
	"scas/client/common"
	"scas/pkg/helper"
	"scas/pkg/testutils"
)

type testSQL struct {
	*sqlStoreImpl

	projectID string
}

func (s *testSQL) updateStatus(ctx context.Context, projectID string, certID string, status common.Status) error {
	log.Debugf("updateStatus(): project=%s, cert=%s", projectID, certID)

	cert, err := s.getCertificate(ctx, projectID, certID)
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
)

func newSQL(ctx context.Context, t *testing.T, dburl string) *testSQL {
	s := testSQL{sqlStoreImpl: NewSQL(dburl).(*sqlStoreImpl)}

	project := testutils.Must1(s.createProject(ctx, testProjectName))
	rootCA := testutils.Must1(s.CreateCA(ctx, project.ID, nil, nil, nil, nil))
	subCA := testutils.Must1(s.CreateCA(ctx, project.ID, nil, nil, nil, &rootCA.ID))
	testutils.Must1(s.CreateCertificate(ctx, project.ID, &provider.CreateRequest{
		CommonName:   "server.example.com",
		KeyAlgorithm: x509.ECDSAWithSHA384,
		NotAfter:     helper.AfterNow(1, 0, 0),
		NotBefore:    helper.AfterNow(0, -1, 0),
	}, nil, nil, nil, subCA.ID))

	cert := testutils.Must1(s.CreateCertificate(ctx, project.ID, &provider.CreateRequest{
		CommonName:   "invalid.example.com",
		KeyAlgorithm: x509.ECDSAWithSHA256,
		NotAfter:     helper.AfterNow(1, 0, 0),
		NotBefore:    helper.AfterNow(0, -1, 0),
	}, nil, nil, nil, subCA.ID))
	require.NoError(t, s.updateStatus(ctx, cert.ProjectID, cert.ID, common.StatusSuspended))

	s.projectID = project.ID
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

				got, err := s.listCertificate(ctx, s.projectID, tt.args.opts)
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
