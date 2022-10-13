package repository

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	"scas/certmanager/provider"
	"scas/certmanager/store"
	"scas/certmanager/types"
	"scas/client/common"
	"scas/client/common/x509types"
	"scas/config"
	"scas/pkg/helper"
	"scas/pkg/helper/x509x"
)

type Interface interface {
	CreateProject(ctx context.Context, projectName string) (*types.Project, error)
	GetProject(ctx context.Context, projectID string) (*types.Project, error)
	ListProject(ctx context.Context, opts store.ProjectListOpt) ([]*types.Project, error)

	CreateCAPool(ctx context.Context, projectID string, poolName string) (*types.CAPool, error)
	GetCAPool(ctx context.Context, projectID, caPoolID string) (*types.CAPool, error)
	ListCAPool(ctx context.Context, projectID string, opts store.CAPoolListOpt) ([]*types.CAPool, error)

	CreateCertificateAuthority(ctx context.Context, projectID string, poolID string, req *provider.CreateRequest, parentCAID string) (*types.CertificateAuthority, error)
	GetCertificateAuthority(ctx context.Context, projectID string, poolID string, ID string) (*types.CertificateAuthority, error)

	CreateCertificate(ctx context.Context, projectID string, poolID string, req *provider.CreateRequest, CAID string) (*types.Certificate, error)
	ListCertificate(ctx context.Context, projectID string, poolID string, opts store.CertificateListOpt) ([]*types.Certificate, error)
	GetCertificate(ctx context.Context, projectID, poolID, ID string) (*types.Certificate, error)
	RenewCertificate(ctx context.Context, projectID string, poolID string, certID string) (*types.Certificate, error)
	RevokeCertificate(ctx context.Context, projectID string, poolID string, certID string, reason x509types.RevokeReason) (*types.Certificate, error)
	GetCRL(ctx context.Context, projectID string, poolID string) ([]byte, error)

	// caller must close channel to close go routine
	CRLUpdateChecker() chan<- struct{}
}

// New create new repository
func New(provider provider.Interface, store store.Interface) Interface {
	return &repoImpl{
		provider: provider,
		store:    store,
		crls:     make(map[string]*crlInfo),
	}
}

type repoImpl struct {
	provider provider.Interface
	store    store.Interface

	crls  map[string]*crlInfo // project_id/capool_id
	muCRL sync.Mutex

	lastCRLUpdateChecked time.Time
}

var _ Interface = (*repoImpl)(nil)

type crlInfo struct {
	template *x509.RevocationList
	crlBytes []byte
}

func (repo *repoImpl) CreateProject(ctx context.Context, name string) (*types.Project, error) {
	proj, err := repo.store.CreateProject(ctx, name)
	if err != nil {
		return nil, errors.Wrap(err, "fail to create project")
	}
	return proj, nil
}

func (repo *repoImpl) GetProject(ctx context.Context, projectID string) (*types.Project, error) {
	return repo.store.GetProject(ctx, projectID)
}

func (repo *repoImpl) ListProject(ctx context.Context, opts store.ProjectListOpt) ([]*types.Project, error) {
	return repo.store.ListProject(ctx, opts)
}

func (repo *repoImpl) CreateCAPool(ctx context.Context, projectID string, poolName string) (*types.CAPool, error) {
	caPool, err := repo.store.CreateCAPool(ctx, projectID, poolName)
	if err != nil {
		return nil, errors.Wrap(err, "fail to create CA pool")
	}
	return caPool, nil
}

func (repo *repoImpl) GetCAPool(ctx context.Context, projectID string, caPoolID string) (*types.CAPool, error) {
	return repo.store.GetCAPool(ctx, projectID, caPoolID)
}

func (repo *repoImpl) ListCAPool(ctx context.Context, projectID string, opts store.CAPoolListOpt) ([]*types.CAPool, error) {
	return repo.store.ListCAPool(ctx, projectID, opts)
}

func (repo *repoImpl) CreateCertificateAuthority(ctx context.Context, projectID string, caPoolID string, req *provider.CreateRequest, parentCAID string) (*types.CertificateAuthority, error) {
	certPEM, certPrivateKeyPEM, err := repo.createCertificate(ctx, projectID, caPoolID, req, parentCAID)
	if err != nil {
		return nil, err
	}

	ca, err := repo.store.CreateCA(ctx, projectID, caPoolID, req, certPEM, certPrivateKeyPEM, fx.Ternary(parentCAID == "", nil, &parentCAID))
	if err != nil {
		return nil, errors.Wrap(err, "fail to create certificate authority")
	}

	return ca, nil
}

// createCertificate create certificate with provider and returns cert, privateKey, error
func (repo *repoImpl) createCertificate(ctx context.Context, projectID string, caPoolID string, req *provider.CreateRequest, parentCAID string) ([]byte, []byte, error) {
	if err := helper.ValidateStruct(req); err != nil {
		return nil, nil, errors.Wrap(err, "fail to create certificate")
	}

	// get parent for signer
	var parent *x509.Certificate
	var parentPrivateKey x509x.PrivateKey
	if parentCAID != "" {
		ca, err := repo.store.GetCA(ctx, projectID, caPoolID, parentCAID)
		if err != nil {
			return nil, nil, errors.Wrap(err, "fail to create certificate")
		}

		parent, err = x509x.ParseCertificate(ca.Cert)
		if err != nil {
			return nil, nil, errors.Wrap(err, "fail to create certificate")
		}

		parentPrivateKey, err = x509x.ParsePrivateKey(ca.Key)
		if err != nil {
			return nil, nil, errors.Wrap(err, "fail to create certificate")
		}
	}

	return repo.provider.CreateCertificate(ctx, req, parent, parentPrivateKey)
}

func (repo *repoImpl) GetCertificateAuthority(ctx context.Context, projectID string, poolID string, ID string) (*types.CertificateAuthority, error) {
	return repo.store.GetCA(ctx, projectID, poolID, ID)
}

func (repo *repoImpl) CreateCertificate(ctx context.Context, projectID string, caPoolID string, req *provider.CreateRequest, CAID string) (*types.Certificate, error) {
	certPEM, certPrivateKeyPEM, err := repo.createCertificate(ctx, projectID, caPoolID, req, CAID)
	if err != nil {
		return nil, err
	}

	chainPEM, err := repo.getCertChain(ctx, projectID, caPoolID)
	if err != nil {
		return nil, errors.Wrap(err, "fail to create certificate")
	}

	cert, err := repo.store.CreateCertificate(ctx, projectID, caPoolID, req, certPEM, certPrivateKeyPEM, chainPEM, CAID)
	if err != nil {
		return nil, errors.Wrap(err, "fail to create certificate")
	}

	return &types.Certificate{
		ID:      cert.ID,
		Cert:    cert.Cert,
		Key:     cert.Key,
		Chain:   cert.Chain,
		Created: cert.Created,
	}, nil
}

func (repo *repoImpl) getCertChain(ctx context.Context, projectID, caPoolID string) ([]byte, error) {
	caList, err := repo.store.ListCA(ctx, projectID, caPoolID, store.CAListOpt{Status: common.StatusActive})
	if len(caList) == 0 {
		panic("empty calist...: status query가 잘 안되는 듯...")
	}

	if err != nil {
		return nil, errors.Wrap(err, "fail to create certificate authority")
	}

	return bytes.Join(fx.Map(caList, func(x *types.CertificateAuthority) []byte { return x.Cert }), []byte{}), nil
}

func (repo *repoImpl) ListCertificate(ctx context.Context, projectID string, poolID string, opts store.CertificateListOpt) ([]*types.Certificate, error) {
	return repo.store.ListCertificate(ctx, projectID, poolID, opts)
}

func (repo *repoImpl) GetCertificate(ctx context.Context, projectID string, poolID string, ID string) (*types.Certificate, error) {
	return repo.store.GetCertificate(ctx, projectID, poolID, ID)
}

// TODO renew subordinate ca, root ca
func (repo *repoImpl) RenewCertificate(ctx context.Context, projectID string, caPoolID string, certID string) (*types.Certificate, error) {
	cert, err := repo.store.GetCertificate(ctx, projectID, caPoolID, certID)
	if err != nil {
		return nil, errors.Wrap(err, "fail to renew certificate")
	}

	req := new(provider.CreateRequest)
	if err := json.Unmarshal([]byte(cert.Request), req); err != nil {
		return nil, errors.Wrap(err, "fail to renew certificate")
	}
	log.Debugf("renew certificate: request=%v", req)

	ca, err := repo.store.GetCA(ctx, projectID, caPoolID, cert.CAID)
	if err != nil {
		return nil, errors.Wrap(err, "fail to rewew certificate")
	}

	caX509Cert, err := x509x.ParseCertificate(ca.Cert)
	if err != nil {
		return nil, errors.Wrap(err, "fail to rewew certificate")
	}

	caX509Key, err := x509x.ParsePrivateKey(ca.Key)
	if err != nil {
		return nil, errors.Wrap(err, "fail to rewew certificate")
	}

	certPEMBytes, keyPEMByte, err := repo.provider.CreateCertificate(ctx, req, caX509Cert, caX509Key)
	if err != nil {
		return nil, errors.Wrap(err, "fail to rewew certificate")
	}

	chainPEM, err := repo.getCertChain(ctx, projectID, caPoolID)
	if err != nil {
		return nil, errors.Wrap(err, "fail to rewew certificate")
	}

	newCert, err := repo.store.CreateCertificate(ctx, projectID, caPoolID, req, certPEMBytes, keyPEMByte, chainPEM, cert.CAID)
	if err != nil {
		return nil, errors.Wrap(err, "fail to rewew certificate")
	}

	return newCert, nil
}

func (repo *repoImpl) RevokeCertificate(ctx context.Context, projectID string, caPoolID string, certID string, reason x509types.RevokeReason) (*types.Certificate, error) {
	if err := repo.store.RevokeCertificate(ctx, projectID, caPoolID, certID, reason); err != nil {
		return nil, errors.Wrap(err, "fail to revoke certificate")
	}

	if err := repo.updateCRL(ctx, projectID, caPoolID); err != nil {
		return nil, errors.Wrap(err, "fail to revoke certificate")
	}

	return repo.store.GetCertificate(ctx, projectID, caPoolID, certID)
}

func (repo *repoImpl) updateCRL(ctx context.Context, projectID, caPoolID string) error {
	log.Debugf("update CRL: project=%s, pool=%s", projectID, caPoolID)

	certs, err := repo.store.ListCertificate(ctx, projectID, caPoolID, store.CertificateListOpt{Status: common.StatusRevoked})
	if err != nil {
		return errors.Wrap(err, "fail to update CRL")
	}

	currentCRL, exists := repo.crls[projectID+"/"+caPoolID]
	nextNumber := big.NewInt(1)
	if exists {
		nextNumber = currentCRL.template.Number.Add(currentCRL.template.Number, big.NewInt(1))
	}

	template := &x509.RevocationList{
		Number:     nextNumber,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(config.CRLNextUpdateDuration()),
	}

	for _, cert := range certs {
		x509Cert, err := x509x.ParseCertificate(cert.Cert)
		if err != nil {
			return errors.Wrap(err, "fail to update CRL")
		}
		template.RevokedCertificates = append(template.RevokedCertificates, pkix.RevokedCertificate{
			SerialNumber:   x509Cert.SerialNumber,
			RevocationTime: *cert.RevokedAt,
		})
	}

	// get root CA for signer
	cas, err := repo.store.ListCA(ctx, projectID, caPoolID, store.CAListOpt{CAID: store.NullableStringOpt{IsNull: true}})
	if err != nil {
		return errors.Wrap(err, "fail to update CRL")
	}
	rootCA, err := x509x.ParseCertificate(cas[0].Cert)
	if err != nil {
		return errors.Wrap(err, "fail to update CRL")
	}

	issuer := &x509.Certificate{
		SubjectKeyId: rootCA.SubjectKeyId,
		Subject:      rootCA.Issuer,
		KeyUsage:     x509.KeyUsageCRLSign,
	}

	signerPrivateKey, err := x509x.GenerateKey(x509.ECDSAWithSHA256)
	if err != nil {
		return errors.Wrap(err, "fail to update CRL")
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, issuer, signerPrivateKey)
	if err != nil {
		return errors.Wrap(err, "fail to update CRL")
	}

	// TODO CRL을 DB에 넣어야할까???
	repo.muCRL.Lock()
	defer repo.muCRL.Unlock()

	repo.crls[projectID+"/"+caPoolID] = &crlInfo{
		template: template,
		crlBytes: crlBytes,
	}

	return nil
}

func (repo *repoImpl) GetCRL(ctx context.Context, projectID string, caPoolID string) ([]byte, error) {
	crl, ok := repo.crls[projectID+"/"+caPoolID]
	if !ok {
		if err := repo.updateCRL(ctx, projectID, caPoolID); err != nil {
			return nil, errors.Wrap(err, "fail to get crl")
		}
		crl = repo.crls[projectID+"/"+caPoolID]
	}

	if crl.template.NextUpdate.Before(time.Now()) {
		if err := repo.updateCRL(ctx, projectID, caPoolID); err != nil {
			return nil, errors.Wrap(err, "fail to get crl")
		}
		crl = repo.crls[projectID+"/"+caPoolID]
	}

	return crl.crlBytes, nil
}

func (repo *repoImpl) CRLUpdateChecker() chan<- struct{} {
	ch := make(chan struct{})

	go func() {
		for x := range ch {
			_ = x

			ctx := context.Background()
			if err := repo.crlUpdateCheck(ctx); err != nil {
				log.Errorf("CRL Update check failed: %v", err)
			}
		}
	}()

	return ch
}

func (repo *repoImpl) crlUpdateCheck(ctx context.Context) (err error) {
	log.Debugf("check CRL need to update..")

	fx.ForEachMap(repo.crls, func(k string, v *crlInfo) {
		s := strings.Split(k, "/")
		projectID, caPoolID := s[0], s[1]

		if v.template.NextUpdate.After(time.Now()) {
			if ee := repo.updateCRL(ctx, projectID, caPoolID); ee != nil {
				err = multierror.Append(errors.Wrapf(err, "fail to crlUpdateCheck: project=%s, pool=%s", projectID, caPoolID))
			}
		}
	})

	if err != nil {
		return err
	}

	repo.lastCRLUpdateChecked = time.Now().UTC()
	return nil
}
