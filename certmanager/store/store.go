package store

import (
	"context"

	"scas/certmanager/provider"
	"scas/certmanager/types"
	"scas/client/common"
	"scas/client/common/x509types"
)

// Interface storage intrface
type Interface interface {
	CreateProject(ctx context.Context, name string) (*types.Project, error)
	GetProject(ctx context.Context, id string) (*types.Project, error)
	ListProject(ctx context.Context, opts ProjectListOpt) ([]*types.Project, error)

	CreateCAPool(ctx context.Context, projectID string, caPoolID string) (*types.CAPool, error)
	GetCAPool(ctx context.Context, projectID string, caPoolID string) (*types.CAPool, error)
	ListCAPool(ctx context.Context, projectID string, opts CAPoolListOpt) ([]*types.CAPool, error)

	// Create New CA Row
	CreateCA(ctx context.Context, projectID, caPoolID string, req *provider.CreateRequest, certPEM, keyPEM []byte, parentCAID *string) (ca *types.CertificateAuthority, err error)
	ListCA(ctx context.Context, projectID, caPoolID string, opts CAListOpt) ([]*types.CertificateAuthority, error)
	GetCA(ctx context.Context, projectID, caPoolID, ID string) (*types.CertificateAuthority, error)

	// Create new certificate
	CreateCertificate(ctx context.Context, projectID, caPoolID string, req *provider.CreateRequest, certPEM, keyPEM, chainPEM []byte, parentCAID string) (ca *types.Certificate, err error)
	GetCertificate(ctx context.Context, projectID, caPoolID string, certID string) (ca *types.Certificate, err error)
	ListCertificate(ctx context.Context, projectID, caPoolID string, opts CertificateListOpt) ([]*types.Certificate, error)
	RevokeCertificate(ctx context.Context, projectID, caPoolID string, certID string, reason x509types.RevokeReason) error
}

type ListCAPoolOpt struct {
}

type CAListOpt struct {
	ID     string
	CAID   NullableStringOpt
	Status common.Status
}

type NullableStringOpt struct {
	IsNull bool
	Value  string
}

func (n *NullableStringOpt) String() string   { return n.Value }
func (n *NullableStringOpt) StringP() *string { return &n.Value }

type CertificateListOpt struct {
	ID     string
	CN     string
	Status common.Status
}
