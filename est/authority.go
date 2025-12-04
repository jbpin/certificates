package est

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/smallstep/pkcs7"
	smallscep "github.com/smallstep/scep"

	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/authority/provisioner"
)

// Authority handles EST interactions.
type Authority struct {
	signAuth             SignAuthority
	roots                []*x509.Certificate
	intermediates        []*x509.Certificate
	defaultSigner        crypto.Signer
	signerCertificate    *x509.Certificate
	estProvisionerNames  []string
	provisionersMutex    sync.RWMutex
}

type authorityKey struct{}

// SignAuthority is the interface for a signing authority.
type SignAuthority interface {
	SignWithContext(ctx context.Context, cr *x509.CertificateRequest, opts provisioner.SignOptions, signOpts ...provisioner.SignOption) ([]*x509.Certificate, error)
	LoadProvisionerByName(string) (provisioner.Interface, error)
}

// NewContext adds the given authority to the context.
func NewContext(ctx context.Context, a *Authority) context.Context {
	return context.WithValue(ctx, authorityKey{}, a)
}

// FromContext returns the current authority from the given context.
func FromContext(ctx context.Context) (a *Authority, ok bool) {
	a, ok = ctx.Value(authorityKey{}).(*Authority)
	return
}

// MustFromContext returns the current authority from the given context. It will
// panic if the authority is not in the context.
func MustFromContext(ctx context.Context) *Authority {
	var (
		a  *Authority
		ok bool
	)
	if a, ok = FromContext(ctx); !ok {
		panic("est authority is not in the context")
	}
	return a
}

// New returns a new Authority that implements the EST interface.
func New(signAuth SignAuthority, opts Options) (*Authority, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	return &Authority{
		signAuth:            signAuth,
		roots:               opts.Roots,
		intermediates:       opts.Intermediates,
		defaultSigner:       opts.Signer,
		signerCertificate:   opts.SignerCert,
		estProvisionerNames: opts.ESTProvisionerNames,
	}, nil
}

// Validate validates if the EST Authority has a valid configuration.
func (a *Authority) Validate() error {
	if a == nil {
		return nil
	}

	a.provisionersMutex.RLock()
	defer a.provisionersMutex.RUnlock()

	for _, name := range a.estProvisionerNames {
		p, err := a.LoadProvisionerByName(name)
		if err != nil {
			return fmt.Errorf("failed loading provisioner %q: %w", name, err)
		}
		if _, ok := p.(*provisioner.EST); ok {
			continue
		}
	}

	return nil
}

// UpdateProvisioners updates the EST Authority with the new, and hopefully
// current EST provisioners configured. This allows the Authority to be
// validated with the latest data.
func (a *Authority) UpdateProvisioners(estProvisionerNames []string) {
	if a == nil {
		return
	}

	a.provisionersMutex.Lock()
	defer a.provisionersMutex.Unlock()

	a.estProvisionerNames = estProvisionerNames
}

// LoadProvisionerByName calls out to the SignAuthority interface to load a
// provisioner by name.
func (a *Authority) LoadProvisionerByName(name string) (provisioner.Interface, error) {
	return a.signAuth.LoadProvisionerByName(name)
}

// GetCACertificates returns the certificate chain for the CA.
func (a *Authority) GetCACertificates(ctx context.Context) (certs []*x509.Certificate, err error) {
	p := provisionerFromContext(ctx)

	if signerCert, _ := p.GetSigner(); signerCert != nil {
		certs = append(certs, signerCert)
	}

	if p.ShouldIncludeIntermediateInChain() || len(certs) == 0 {
		certs = append(certs, a.intermediates...)
	}

	if p.ShouldIncludeRootInChain() {
		certs = append(certs, a.roots...)
	}

	return certs, nil
}

// SignCSR signs the CSR using the provisioner and returns the issued chain.
func (a *Authority) SignCSR(ctx context.Context, csr *x509.CertificateRequest, signCSROpts ...provisioner.SignCSROption) ([]*x509.Certificate, error) {
	p := provisionerFromContext(ctx)

	// Template data
	sans := []string{}
	sans = append(sans, csr.DNSNames...)
	sans = append(sans, csr.EmailAddresses...)
	for _, v := range csr.IPAddresses {
		sans = append(sans, v.String())
	}
	for _, v := range csr.URIs {
		sans = append(sans, v.String())
	}
	if len(sans) == 0 {
		sans = append(sans, csr.Subject.CommonName)
	}
	data := x509util.CreateTemplateData(csr.Subject.CommonName, sans)
	data.SetCertificateRequest(csr)
	data.SetSubject(x509util.Subject{
		Country:            csr.Subject.Country,
		Organization:       csr.Subject.Organization,
		OrganizationalUnit: csr.Subject.OrganizationalUnit,
		Locality:           csr.Subject.Locality,
		Province:           csr.Subject.Province,
		StreetAddress:      csr.Subject.StreetAddress,
		PostalCode:         csr.Subject.PostalCode,
		SerialNumber:       csr.Subject.SerialNumber,
		CommonName:         csr.Subject.CommonName,
	})

	for _, o := range signCSROpts {
		if m, ok := o.(provisioner.TemplateDataModifier); ok {
			m.Modify(data)
		}
	}

	ctx = provisioner.NewContextWithMethod(ctx, provisioner.SignMethod)
	signOps, err := p.AuthorizeSign(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("error retrieving authorization options from EST provisioner: %w", err)
	}
	for _, signOp := range signOps {
		if wc, ok := signOp.(*provisioner.WebhookController); ok {
			wc.TemplateData = data
		}
	}

	opts := provisioner.SignOptions{}
	templateOptions, err := provisioner.TemplateOptions(p.GetOptions(), data)
	if err != nil {
		return nil, fmt.Errorf("error creating template options from EST provisioner: %w", err)
	}
	signOps = append(signOps, templateOptions)

	certChain, err := a.signAuth.SignWithContext(ctx, csr, opts, signOps...)
	if err != nil {
		return nil, fmt.Errorf("error generating certificate: %w", err)
	}

	return certChain, nil
}

// BuildSignedChain returns a PKCS7 signedData structure containing the cert chain.
func (a *Authority) BuildSignedChain(ctx context.Context, certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates to encode")
	}

	// Build degenerate PKCS7 from chain.
	deg, err := smallscep.DegenerateCertificates(certs)
	if err != nil {
		return nil, fmt.Errorf("failed generating degenerate certificate: %w", err)
	}

	signerCert, signer, err := a.selectSigner(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed selecting signer: %w", err)
	}

	signedData, err := pkcs7.NewSignedData(deg)
	if err != nil {
		return nil, err
	}
	if err := signedData.AddSigner(signerCert, signer, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}

	return signedData.Finish()
}

// ValidateChallenge validates the provided shared secret using the provisioner.
func (a *Authority) ValidateChallenge(ctx context.Context, secret string) error {
	p := provisionerFromContext(ctx)
	return p.ValidateSharedSecret(ctx, secret)
}

func (a *Authority) selectSigner(ctx context.Context) (cert *x509.Certificate, signer crypto.Signer, err error) {
	p := provisionerFromContext(ctx)
	cert, signer = p.GetSigner()
	switch {
	case cert != nil && signer != nil:
		return
	case cert == nil && signer != nil:
		return nil, nil, fmt.Errorf("provisioner %q does not have a signer certificate available", p.GetName())
	case cert != nil && signer == nil:
		return nil, nil, fmt.Errorf("provisioner %q does not have a signer available", p.GetName())
	}

	cert, signer = a.signerCertificate, a.defaultSigner
	switch {
	case cert == nil && signer != nil:
		return nil, nil, fmt.Errorf("provisioner %q does not have a default signer certificate available", p.GetName())
	case cert != nil && signer == nil:
		return nil, nil, fmt.Errorf("provisioner %q does not have a default signer available", p.GetName())
	}

	return
}
