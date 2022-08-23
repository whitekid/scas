package store

import (
	"context"
	"encoding/json"

	"github.com/lithammer/shortuuid/v4"
	"github.com/pkg/errors"
	"github.com/whitekid/goxp"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"
	"gorm.io/gorm"

	"scas/certmanager/provider"
	"scas/certmanager/store/models"
	"scas/certmanager/types"
	"scas/client/common"
	"scas/client/common/x509types"
	"scas/pkg/helper"
	"scas/pkg/helper/gormx"
)

var (
	ErrInvalidStatus = errors.New("invalid status")
)

// sqlStoreImpl store to SQL Server
type sqlStoreImpl struct {
	db *gorm.DB
}

var _ Interface = (*sqlStoreImpl)(nil)

// NewSQL create new SQL store
func NewSQL(dburl string) Interface {
	db, err := gormx.Open(dburl)
	if err != nil {
		panic(err)
	}

	if err := models.Migrate(db); err != nil {
		panic(err)
	}

	return &sqlStoreImpl{
		db: db,
	}
}

func (s *sqlStoreImpl) CreateProject(ctx context.Context, name string) (*types.Project, error) {
	log.Debugf("CreateProject(): name=%s", name)
	return s.createProject(ctx, shortuuid.New(), name)
}

func (s *sqlStoreImpl) GetProject(ctx context.Context, id string) (*types.Project, error) {
	log.Debugf("GetProject(): project=%s", id)

	results, err := s.ListProject(ctx, ProjectListOpt{ID: id})
	if err != nil {
		return nil, errors.Wrap(err, "GetProject() failed")
	}

	switch len(results) {
	case 0:
		return nil, gorm.ErrRecordNotFound
	case 1:
		return results[0], nil
	default:
		return nil, ErrMultipleRecord
	}
}

type ProjectListOpt struct {
	ID string
}

func (s *sqlStoreImpl) ListProject(ctx context.Context, opts ProjectListOpt) ([]*types.Project, error) {
	results, err := s.listProject(ctx, opts)
	if err != nil {
		return nil, errors.Wrap(err, "fail to ListProject()")
	}
	return fx.Map(results, func(x *models.Project) *types.Project {
		return &types.Project{
			ID:      x.ID,
			Name:    x.Name,
			Created: x.CreatedAt,
		}
	}), nil
}

func (s *sqlStoreImpl) listProject(ctx context.Context, opts ProjectListOpt) ([]*models.Project, error) {
	log.Debugf("listProject(): opts=%+v", opts)

	w := &models.Project{
		ID: opts.ID,
	}

	tx := s.db.Order("created_at")

	var results []*models.Project
	if tx := tx.Find(&results, w); tx.Error != nil {
		return nil, errors.Wrap(gormx.ConvertSQLError(tx.Error), "listProject() failed")
	}

	return results, nil
}

func (s *sqlStoreImpl) createProject(ctx context.Context, id, name string) (*types.Project, error) {
	project := &models.Project{ID: id, Name: name}
	if tx := s.db.Create(project); tx.Error != nil {
		return nil, gormx.ConvertSQLError(tx.Error)
	}

	return &types.Project{
		ID:      project.ID,
		Name:    project.Name,
		Created: project.CreatedAt,
	}, nil
}

func (s *sqlStoreImpl) CreateCAPool(ctx context.Context, projectID string, caPoolName string) (*types.CAPool, error) {
	log.Debugf("CreateCAPool(): project=%s, capool=%s", projectID, caPoolName)
	return s.createCAPool(ctx, projectID, shortuuid.New(), caPoolName)
}

func (s *sqlStoreImpl) createCAPool(ctx context.Context, projectID string, id, name string) (*types.CAPool, error) {
	if err := helper.ValidateStruct(&struct {
		ProjectID string `validate:"required"`
		ID        string `validate:"required"`
		Name      string `validate:"required"`
	}{
		ProjectID: projectID,
		ID:        id,
		Name:      name,
	}); err != nil {
		return nil, err
	}

	capool := &models.CAPool{
		ID:        id,
		Name:      name,
		ProjectID: projectID,
	}
	if tx := s.db.Create(capool); tx.Error != nil {
		return nil, gormx.ConvertSQLError(tx.Error)
	}

	return s.GetCAPool(ctx, projectID, id)
}

func (s *sqlStoreImpl) GetCAPool(ctx context.Context, projectID string, caPoolID string) (*types.CAPool, error) {
	log.Debugf("GetCAPool: project=%s, caPoolID=%s", projectID, caPoolID)

	results, err := s.ListCAPool(ctx, projectID, CAPoolListOpt{ID: caPoolID})
	if err != nil {
		return nil, errors.Wrap(err, "GetCAPool() failed")
	}

	switch len(results) {
	case 0:
		return nil, gorm.ErrRecordNotFound
	case 1:
		return results[0], nil
	default:
		return nil, ErrMultipleRecord
	}
}

type CAPoolListOpt struct {
	ID string
}

func (s *sqlStoreImpl) ListCAPool(ctx context.Context, projectID string, opts CAPoolListOpt) ([]*types.CAPool, error) {
	results, err := s.listCAPool(ctx, projectID, opts)
	if err != nil {
		return nil, errors.Wrap(err, "fail to ListCAPool()")
	}
	return fx.Map(results, func(x *models.CAPool) *types.CAPool {
		return &types.CAPool{
			ID:        x.ID,
			Name:      x.Name,
			ProjectID: x.ProjectID,
			Created:   x.CreatedAt,
		}
	}), nil
}

func (s *sqlStoreImpl) listCAPool(ctx context.Context, projectID string, opts CAPoolListOpt) ([]*models.CAPool, error) {
	log.Debugf("listCAPool: project=%s, opts=%+v", projectID, opts)

	w := &models.CAPool{
		ProjectID: projectID,
		ID:        opts.ID,
	}

	tx := s.db.Order("created_at")

	var results []*models.CAPool
	if tx := tx.Find(&results, w); tx.Error != nil {
		return nil, errors.Wrap(gormx.ConvertSQLError(tx.Error), "listCAPool() failed")
	}

	return results, nil
}

func (s *sqlStoreImpl) CreateCA(ctx context.Context, projectID, caPoolID string, req *provider.CreateRequest, certPEM, keyPEM []byte, parentCAID *string) (ca *types.CertificateAuthority, err error) {
	ID := shortuuid.New()

	log.Debugf("CreateCA: ID=%s, project=%s, capool=%s, req=%v, parent=%+v", ID, projectID, caPoolID, req, parentCAID)
	if parentCAID != nil {
		log.Debugf("\tparentCA=%s", *parentCAID)
		if _, err := s.GetCA(ctx, projectID, caPoolID, *parentCAID); err != nil {
			return nil, errors.Errorf("parent ca not found")
		}
	}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "fail to create certficiate authority")
	}

	if tx := s.db.Create(&models.CertificateAuthority{
		ID:        ID,
		ProjectID: projectID,
		CAPoolID:  caPoolID,
		Request:   reqJSON,
		Cert:      certPEM,
		Key:       keyPEM,
		CAID:      parentCAID,
		Status:    common.StatusActive.String(),
	}); tx.Error != nil {
		return nil, gormx.ConvertSQLError(tx.Error)
	}

	return s.GetCA(ctx, projectID, caPoolID, ID)
}

func (s *sqlStoreImpl) ListCA(ctx context.Context, projectID, caPoolID string, opts CAListOpt) ([]*types.CertificateAuthority, error) {
	log.Debugf("ListCA: project=%s, capool=%s, opts=%v", projectID, caPoolID, opts)

	w := &models.CertificateAuthority{
		ProjectID: projectID,
		CAPoolID:  caPoolID,
		ID:        opts.ID,
		Status:    opts.Status.String(),
	}

	tx := s.db.Order("created_at")
	if opts.CAID.IsNull {
		tx = tx.Where("ca_id IS NULL")
	} else {
		if opts.CAID.String() != "" {
			w.CAID = opts.CAID.StringP()
		}
	}

	var results []*models.CertificateAuthority
	if tx := tx.Find(&results, w); tx.Error != nil {
		return nil, errors.Wrap(gormx.ConvertSQLError(tx.Error), "ListCA() failed")
	}

	return fx.Map(results, func(cert *models.CertificateAuthority) *types.CertificateAuthority {
		return &types.CertificateAuthority{
			ID:        cert.ID,
			ProjectID: cert.ProjectID,
			CAPoolID:  cert.CAPoolID,
			Request:   string(cert.Request),
			Cert:      cert.Cert,
			Key:       cert.Key,
			Created:   cert.CreatedAt,
			CAID:      cert.CAID,
			Status:    common.StrToStatus(cert.Status),
		}
	}), nil
}

func (s *sqlStoreImpl) GetCA(ctx context.Context, projectID, caPoolID, ID string) (*types.CertificateAuthority, error) {
	log.Debugf("GetCA: project=%s, capool=%s, ID=%s", projectID, caPoolID, ID)

	results, err := s.ListCA(ctx, projectID, caPoolID, CAListOpt{ID: ID})
	if err != nil {
		return nil, errors.Wrap(err, "fail to get certificate authority")
	}

	switch len(results) {
	case 0:
		return nil, gorm.ErrRecordNotFound
	case 1:
		return results[0], nil
	default:
		return nil, ErrMultipleRecord
	}
}

func (s *sqlStoreImpl) CreateCertificate(ctx context.Context, projectID, caPoolID string, req *provider.CreateRequest, certPEM, keyPEM, chainPEM []byte, parentCAID string) (ca *types.Certificate, err error) {
	if err := helper.ValidateVar(req, "required"); err != nil {
		return nil, errors.Wrap(err, "fail to create certficiate")
	}

	if err := helper.ValidateStruct(req); err != nil {
		return nil, errors.Wrap(err, "fail to create certficiate")
	}

	certID := shortuuid.New()

	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "fail to create certficiate")
	}

	if tx := s.db.Create(&models.Certificate{
		ID:        certID,
		CAID:      parentCAID,
		ProjectID: projectID,
		CAPoolID:  caPoolID,
		Request:   reqJSON,
		Cert:      certPEM,
		Chain:     chainPEM,
		Key:       keyPEM,
		Status:    common.StatusActive.String(),

		CN: req.CommonName,
	}); tx.Error != nil {
		return nil, gormx.ConvertSQLError(tx.Error)
	}

	return s.GetCertificate(ctx, projectID, caPoolID, certID)
}

func (s *sqlStoreImpl) GetCertificate(ctx context.Context, projectID, caPoolID, certID string) (*types.Certificate, error) {
	results, err := s.ListCertificate(ctx, projectID, caPoolID, CertificateListOpt{ID: certID})
	if err != nil {
		return nil, errors.Wrap(err, "fail to get certifciate")
	}

	switch len(results) {
	case 0:
		return nil, gorm.ErrRecordNotFound
	case 1:
		return results[0], nil
	default:
		return nil, ErrMultipleRecord
	}
}

func (s *sqlStoreImpl) getCertificate(ctx context.Context, projectID, caPoolID, certID string) (*models.Certificate, error) {
	results, err := s.listCertificate(ctx, projectID, caPoolID, CertificateListOpt{ID: certID})
	if err != nil {
		return nil, errors.Wrap(err, "fail to get certifciate")
	}

	switch len(results) {
	case 0:
		return nil, gorm.ErrRecordNotFound
	case 1:
		return results[0], nil
	default:
		return nil, ErrMultipleRecord
	}
}

func (s *sqlStoreImpl) ListCertificate(ctx context.Context, projectID string, caPoolID string, opts CertificateListOpt) ([]*types.Certificate, error) {
	results, err := s.listCertificate(ctx, projectID, caPoolID, opts)
	if err != nil {
		return nil, errors.Wrap(err, "ListCertificate() failed")
	}

	return fx.Map(results, func(cert *models.Certificate) *types.Certificate {
		return &types.Certificate{
			ID:            cert.ID,
			CAID:          cert.CAID,
			ProjectID:     cert.ProjectID,
			CAPoolID:      cert.CAPoolID,
			Request:       string(cert.Request),
			Cert:          cert.Cert,
			Key:           cert.Key,
			Chain:         cert.Chain,
			Status:        common.StrToStatus(cert.Status),
			Created:       cert.CreatedAt,
			RevokedAt:     cert.RevokedAt,
			RevokedReason: cert.RevokedReason,

			CN: cert.CN,
		}
	}), nil
}

func (s *sqlStoreImpl) listCertificate(ctx context.Context, projectID string, caPoolID string, opts CertificateListOpt) ([]*models.Certificate, error) {
	log.Debugf("listCertificate(): opts=%+v", opts)

	w := &models.Certificate{
		ID:        opts.ID,
		ProjectID: projectID,
		CAPoolID:  caPoolID,
		CN:        opts.CN,
		Status:    opts.Status.String(),
	}

	goxp.IfThen(opts.Status != common.StatusNone, func() { w.Status = opts.Status.String() })
	log.Debugf("listCertificate(): query=%+v", w)

	var results []*models.Certificate
	if tx := s.db.Order("created_at").Find(&results, w); tx.Error != nil {
		return nil, errors.Wrap(gormx.ConvertSQLError(tx.Error), "listCertificate() failed")
	}

	return results, nil
}

func (s *sqlStoreImpl) RevokeCertificate(ctx context.Context, projectID string, caPoolID string, certID string, reason x509types.RevokeReason) error {
	log.Debugf("RevokeCertificate(): project=%s, capool=%s, cert=%s", projectID, caPoolID, certID)

	cert, err := s.getCertificate(ctx, projectID, caPoolID, certID)
	if err != nil {
		return errors.Wrap(err, "fail to revoke certificate")
	}

	if !fx.Contains([]string{common.StatusActive.String()}, cert.Status) {
		return ErrInvalidStatus
	}

	cert.Status = common.StatusRevoked.String()
	cert.RevokedReason = reason.String()
	cert.RevokedAt = helper.NowP()
	if tx := s.db.Save(cert); tx.Error != nil {
		return errors.Wrap(err, "fail to revoke certificate")
	}

	return nil
}
