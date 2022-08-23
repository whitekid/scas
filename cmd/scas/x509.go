package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/whitekid/goxp/fx"

	"scas/pkg/helper"
	"scas/pkg/helper/x509x"
)

var x509cmd *cobra.Command

func init() {
	x509cmd = &cobra.Command{
		Use:   "x509",
		Short: "x509 utility commands",
	}
	rootCmd.AddCommand(x509cmd)
}

func init() {
	cmd := &cobra.Command{
		Use: "csr",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "info csr",
		Short: "show CSR informations",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if err := csrInfo(cmd.Context(), arg); err != nil {
					return err
				}
			}
			return nil
		},
	})

	x509cmd.AddCommand(cmd)
}

// csrInfo show csr information
// openssl req -text in <filename>
func csrInfo(ctx context.Context, filename string) error {
	pemBytes, err := helper.ReadFile(filename)
	if err != nil {
		return err
	}

	csr, err := x509x.ParseCSR(pemBytes)
	if err != nil {
		return err
	}

	if csr == nil {
		return errors.New("invalid pem")
	}

	return helper.WriteJSON(os.Stdout, &struct {
		Version            int    `json:",omitempty"`
		CommonName         string `json:",omitempty"`
		PublicKeyAlgorithm string `json:",omitempty"`
		Country            string `json:",omitempty"`
		Organization       string `json:",omitempty"`
		OrganizationalUnit string `json:",omitempty"`
		Locality           string `json:",omitempty"`
		Province           string `json:",omitempty"`
		StreetAddress      string `json:",omitempty"`
		Extra              string `json:",omitempty"`
		PostcalCode        string `json:",omitempty"`

		DNSName      string `json:",omitempty"`
		EmailAddress string `json:",omitempty"`
		IPAdress     string `json:",omitempty"`
		URIs         string `json:",omitempty"`

		SerialNumber string `json:",omitempty"`
	}{
		Version:            csr.Version,
		CommonName:         csr.Subject.CommonName,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm.String(),
		Country:            strings.Join(csr.Subject.Country, ", "),
		Organization:       strings.Join(csr.Subject.Organization, ", "),
		OrganizationalUnit: strings.Join(csr.Subject.OrganizationalUnit, ", "),
		Locality:           strings.Join(csr.Subject.Locality, ", "),
		Province:           strings.Join(csr.Subject.Province, ", "),
		StreetAddress:      strings.Join(csr.Subject.StreetAddress, ", "),
		Extra:              strings.Join(fx.Map(csr.Subject.ExtraNames, func(e pkix.AttributeTypeAndValue) string { return e.Type.String() }), ", "),
		PostcalCode:        strings.Join(csr.Subject.PostalCode, ", "),
		DNSName:            strings.Join(csr.DNSNames, ", "),
		EmailAddress:       strings.Join(csr.EmailAddresses, ", "),
		IPAdress:           strings.Join(fx.Map(csr.IPAddresses, func(e net.IP) string { return e.String() }), ", "),
		URIs:               strings.Join(fx.Map(csr.URIs, func(e *url.URL) string { return e.String() }), ", "),
		SerialNumber:       csr.Subject.SerialNumber,
	})
}

func init() {
	cmd := &cobra.Command{
		Use: "cert",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "info cert",
		Short: "show x509 certificate informations",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, filename := range args {
				if err := certInfo(cmd.Context(), filename); err != nil {
					return err
				}
			}
			return nil
		},
	})

	x509cmd.AddCommand(cmd)
}

// certInfo show certification info
// openssl x509 -text -in <filename>
func certInfo(ctx context.Context, filename string) error {
	pemBytes, err := helper.ReadFile(filename)
	if err != nil {
		return err
	}

	certs, err := x509x.ParseCertificateChain(pemBytes)
	if err != nil {
		return err
	}

	fx.ForEach(certs, func(_ int, cert *x509.Certificate) {
		helper.WriteJSON(os.Stdout, &struct {
			Version            int    `json:",omitempty"`
			CommonName         string `json:",omitempty"`
			PublicKeyAlgorithm string `json:",omitempty"`
			Country            string `json:",omitempty"`
			Organization       string `json:",omitempty"`
			OrganizationalUnit string `json:",omitempty"`
			Locality           string `json:",omitempty"`
			Province           string `json:",omitempty"`
			StreetAddress      string `json:",omitempty"`
			Extra              string `json:",omitempty"`
			PostcalCode        string `json:",omitempty"`

			DNSName      string `json:",omitempty"`
			EmailAddress string `json:",omitempty"`
			IPAdress     string `json:",omitempty"`
			URIs         string `json:",omitempty"`

			SerialNumber          string `json:",omitempty"`
			SubjectKeyId          []byte `json:",omitempty"`
			KeyUsage              []string
			ExtKeyUsage           []string
			CRLDistributionPoints string `json:",omitempty"`

			NotAfter  time.Time `json:",omitempty"`
			NotBefore time.Time `json:",omitempty"`

			IssuerCommonName   string
			IssuerSerialNumber string
		}{
			Version:               cert.Version,
			CommonName:            cert.Issuer.CommonName,
			PublicKeyAlgorithm:    cert.PublicKeyAlgorithm.String(),
			Country:               strings.Join(cert.Issuer.Country, ", "),
			Organization:          strings.Join(cert.Issuer.Organization, ", "),
			OrganizationalUnit:    strings.Join(cert.Issuer.OrganizationalUnit, ", "),
			Locality:              strings.Join(cert.Issuer.Locality, ", "),
			Province:              strings.Join(cert.Issuer.Province, ", "),
			StreetAddress:         strings.Join(cert.Issuer.StreetAddress, ", "),
			Extra:                 strings.Join(fx.Map(cert.Issuer.ExtraNames, func(e pkix.AttributeTypeAndValue) string { return e.Type.String() }), ", "),
			PostcalCode:           strings.Join(cert.Issuer.PostalCode, ", "),
			DNSName:               strings.Join(cert.DNSNames, ", "),
			EmailAddress:          strings.Join(cert.EmailAddresses, ", "),
			IPAdress:              strings.Join(fx.Map(cert.IPAddresses, func(e net.IP) string { return e.String() }), ", "),
			URIs:                  strings.Join(fx.Map(cert.URIs, func(e *url.URL) string { return e.String() }), ", "),
			SerialNumber:          cert.SerialNumber.String(),
			SubjectKeyId:          cert.SubjectKeyId,
			KeyUsage:              x509x.KeyUsageToStr(cert.KeyUsage),
			ExtKeyUsage:           x509x.ExtKeyUsageToStr(cert.ExtKeyUsage),
			CRLDistributionPoints: strings.Join(cert.CRLDistributionPoints, ", "),
			NotAfter:              cert.NotAfter,
			NotBefore:             cert.NotBefore,
			IssuerCommonName:      cert.Issuer.CommonName,
			IssuerSerialNumber:    cert.Issuer.SerialNumber,
		})
	})
	return nil
}

func init() {
	cmd := &cobra.Command{
		Use:   "crl",
		Short: "CRL",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "info crl",
		Short: "show CRL",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, filename := range args {
				if err := crlInfo(cmd.Context(), filename); err != nil {
					return err
				}
			}
			return nil
		},
	})

	x509cmd.AddCommand(cmd)
}

func crlInfo(ctx context.Context, filename string) error {
	crlBytes, err := helper.ReadFile(filename)
	if err != nil {
		return err
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return err
	}

	return helper.WriteJSON(os.Stdout, &struct {
		CommonName          string
		Signature           []byte
		SignatureAlgorithm  string
		Number              *big.Int
		ThisUpdate          time.Time
		NextUpdate          time.Time
		RevokedCertificates []pkix.RevokedCertificate
	}{
		CommonName:          crl.Issuer.CommonName,
		Signature:           crl.Signature,
		SignatureAlgorithm:  crl.SignatureAlgorithm.String(),
		Number:              crl.Number,
		ThisUpdate:          crl.ThisUpdate,
		NextUpdate:          crl.NextUpdate,
		RevokedCertificates: crl.RevokedCertificates,
	})
}
