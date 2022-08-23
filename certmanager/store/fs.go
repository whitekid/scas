package store

import (
	"context"

	"scas/certmanager/provider"
	"scas/certmanager/types"
	"scas/client/common/x509types"
)

type fileStoreImpl struct {
}

var _ Interface = (*fileStoreImpl)(nil)

func File() Interface {
	return &fileStoreImpl{}
}
func (f *fileStoreImpl) CreateProject(ctx context.Context, name string) (*types.Project, error) {
	panic("not implemented") // TODO: Implement
}

func (f *fileStoreImpl) GetProject(ctx context.Context, id string) (*types.Project, error) {
	panic("not implemented") // TODO: Implement
}

func (f *fileStoreImpl) ListProject(ctx context.Context, opts ProjectListOpt) ([]*types.Project, error) {
	panic("not implemented") // TODO: Implement
}

func (f *fileStoreImpl) CreateCAPool(ctx context.Context, projectID string, caPoolID string) (*types.CAPool, error) {
	panic("not implemented") // TODO: Implement
}

func (f *fileStoreImpl) GetCAPool(ctx context.Context, projectID string, caPoolID string) (*types.CAPool, error) {
	panic("not implemented") // TODO: Implement
}

func (f *fileStoreImpl) ListCAPool(ctx context.Context, projectID string, opts CAPoolListOpt) ([]*types.CAPool, error) {
	panic("not implemented") // TODO: Implement
}

// Create New CA Row
func (f *fileStoreImpl) CreateCA(ctx context.Context, projectID string, caPoolID string, req *provider.CreateRequest, certPEM []byte, keyPEM []byte, parentCAID *string) (ca *types.CertificateAuthority, err error) {
	panic("not implemented") // TODO: Implement
}

func (f *fileStoreImpl) ListCA(ctx context.Context, projectID string, caPoolID string, opts CAListOpt) ([]*types.CertificateAuthority, error) {
	panic("not implemented") // TODO: Implement
}

func (f *fileStoreImpl) GetCA(ctx context.Context, projectID string, caPoolID string, ID string) (*types.CertificateAuthority, error) {
	panic("not implemented") // TODO: Implement
}

// Create new certificate
func (f *fileStoreImpl) CreateCertificate(ctx context.Context, projectID string, caPoolID string, req *provider.CreateRequest, certPEM []byte, keyPEM []byte, chainPEM []byte, parentCAID string) (ca *types.Certificate, err error) {
	panic("not implemented") // TODO: Implement
}

func (f *fileStoreImpl) GetCertificate(ctx context.Context, projectID string, caPoolID string, certID string) (ca *types.Certificate, err error) {
	panic("not implemented") // TODO: Implement
}

func (f *fileStoreImpl) ListCertificate(ctx context.Context, projectID string, caPoolID string, opts CertificateListOpt) ([]*types.Certificate, error) {
	panic("not implemented") // TODO: Implement
}

func (f *fileStoreImpl) RevokeCertificate(ctx context.Context, projectID string, caPoolID string, certID string, reason x509types.RevokeReason) error {
	panic("not implemented") // TODO: Implement
}
