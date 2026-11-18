package provisioner

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"

	"github.com/smallstep/certificates/webhook"
	"go.step.sm/crypto/x509util"
)

var (
	ErrESTAuthMethodDisabled      = errors.New("est authentication method disabled")
	ErrESTAuthMethodNotFound      = errors.New("no valid est authentication method found")
	ErrESTAuthMethodMisconfigured = errors.New("est authentication method misconfigured")
	ErrESTAuthDenied              = errors.New("est authentication denied")
)

// ClientCertificateConfig holds the EST client certificate authentication configuration.
type ClientCertificateConfig struct {
	Enable                       bool
	ForwardedTLSClientCertHeader string
}

// ESTAuthRequest contains authentication material extracted from the request.
type ESTAuthRequest struct {
	CSR                    *x509.CertificateRequest
	ClientCertificate      *x509.Certificate
	ClientCertificateChain []*x509.Certificate
	CARoots                []*x509.Certificate
	CAIntermediates        []*x509.Certificate
	AuthenticationHeader   string
	BasicAuthUsername      string
	BasicAuthPassword      string
	BearerToken            string
}

func (s *EST) GetClientCertificateConfig() *ClientCertificateConfig {
	return &ClientCertificateConfig{
		Enable:                       boolValue(s.EnableTLSClientCertificate, false),
		ForwardedTLSClientCertHeader: s.ForwardedTLSClientCertHeader,
	}
}

// AuthorizeRequest validates the request against configured EST auth methods.
//
// A client that already holds a certificate this provisioner accepts renews
// with it: the certificate is the authentication and the challenge webhooks
// (enrollment token) are only for first issuance. The CSR must carry the
// certificate's public key, so its signature proves possession of that key: a
// certificate is public and may arrive in a forwarded header that the client
// itself wrote. It must also name exactly the certificate's identity, so one
// device cannot renew as another. A new key means enrolling again.
// Revocation of the client certificate is checked by the caller (est/api).
func (s *EST) AuthorizeRequest(ctx context.Context, req ESTAuthRequest) ([]SignCSROption, error) {
	if req.ClientCertificate != nil && s.verifyClientCertificate(req) == nil {
		if !csrMatchesCertificate(req.CSR, req.ClientCertificate) {
			return nil, ErrESTAuthDenied
		}
		return []SignCSROption{}, nil
	}
	if s.hasAuthWebhooks() {
		return s.authorizeWithWebhook(ctx, &req)
	}
	return s.authorizeRequestLocal(req)
}

// authorizeRequestLocal validates the request using provisioner configuration.
func (s *EST) authorizeRequestLocal(req ESTAuthRequest) ([]SignCSROption, error) {
	var lastErr error = ErrESTAuthMethodNotFound
	if req.ClientCertificate != nil {
		if err := s.verifyClientCertificate(req); err == nil {
			return []SignCSROption{}, nil
		} else {
			lastErr = err
		}
	}

	if req.hasBasicAuth() {
		if boolValue(s.EnableHTTPBasicAuth, false) && s.BasicAuthPassword != "" {
			if err := s.validateBasicAuthPassword(req.BasicAuthUsername, req.BasicAuthPassword); err == nil {
				return []SignCSROption{}, nil
			} else {
				lastErr = err
			}
		} else {
			lastErr = ErrESTAuthMethodDisabled
		}
	}

	return nil, lastErr
}

// verifyClientCertificate checks that client certificate authentication is
// enabled and that the certificate chains to the configured client certificate
// roots, or to the CA itself when none are configured.
func (s *EST) verifyClientCertificate(req ESTAuthRequest) error {
	if !boolValue(s.EnableTLSClientCertificate, false) {
		return ErrESTAuthMethodDisabled
	}
	if s.hasClientCertificateRoots() {
		return verifyCertificateWithPool(req.ClientCertificate, req.ClientCertificateChain, s.clientCertificateRootPool, nil)
	}
	return verifyCertificate(req.ClientCertificate, req.ClientCertificateChain, req.CARoots, req.CAIntermediates)
}

// validateBasicAuthPassword verifies the configured basic auth password.
func (s *EST) validateBasicAuthPassword(username, password string) error {
	if s.BasicAuthUsername != "" && username != s.BasicAuthUsername {
		return errors.New("invalid basic auth")
	}
	if subtleCompare(s.BasicAuthPassword, password) {
		return nil
	}
	return errors.New("invalid basic auth")
}

// authorizeWithWebhook executes configured webhooks for auth decisions.
func (s *EST) authorizeWithWebhook(ctx context.Context, req *ESTAuthRequest) ([]SignCSROption, error) {
	if !s.hasAuthWebhooks() {
		return nil, ErrESTAuthMethodMisconfigured
	}

	// A verified client certificate never gets here (AuthorizeRequest); one
	// that fails verification is dropped, as the request can still
	// authenticate with its Authorization header.
	if req.AuthenticationHeader == "" {
		return nil, ErrESTAuthDenied
	}
	bodyOpts := []webhook.RequestBodyOption{
		webhook.WithX509CertificateRequest(req.CSR),
		webhook.WithAuthenticationHeader(req.AuthenticationHeader),
	}

	whreq, err := webhook.NewRequestBody(bodyOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed creating webhook request: %w", err)
	}
	whreq.BearerToken = req.BearerToken
	whreq.ProvisionerName = s.Name
	var opts []SignCSROption

	for _, wh := range s.challengeValidationController.webhooks {
		resp, err := wh.DoWithContext(ctx, s.challengeValidationController.client, s.challengeValidationController.wrapTransport, whreq, nil)
		if err != nil {
			return nil, fmt.Errorf("failed executing webhook request: %w", err)
		}
		if resp.Allow {
			opts = append(opts, TemplateDataModifierFunc(func(data x509util.TemplateData) {
				data.SetWebhook(wh.Name, resp.Data)
			}))
		}
	}

	if len(opts) == 0 {
		return nil, ErrESTAuthDenied
	}

	return opts, nil
}

// csrMatchesCertificate reports whether the CSR asks for the same key, subject
// and SANs as the certificate. The CSR signature is checked by the caller.
// A CSR without SANs gets its CN as the only SAN (est/authority.go), so that
// is what the certificate must hold.
func csrMatchesCertificate(csr *x509.CertificateRequest, cert *x509.Certificate) bool {
	if csr == nil || !bytes.Equal(csr.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) ||
		csr.Subject.String() != cert.Subject.String() {
		return false
	}
	want := sanStrings(csr.DNSNames, csr.EmailAddresses, csr.IPAddresses, csr.URIs)
	if len(want) == 0 {
		want = []string{csr.Subject.CommonName}
	}
	return sameStrings(want, sanStrings(cert.DNSNames, cert.EmailAddresses, cert.IPAddresses, cert.URIs))
}

func sanStrings(dns, emails []string, ips []net.IP, uris []*url.URL) []string {
	out := append(append([]string{}, dns...), emails...)
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	for _, u := range uris {
		out = append(out, u.String())
	}
	return out
}

func sameStrings(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// hasBasicAuth reports whether any basic auth data is present.
func (r ESTAuthRequest) hasBasicAuth() bool {
	return r.BasicAuthUsername != "" || r.BasicAuthPassword != ""
}

// hasAuthWebhooks reports whether auth webhooks are configured.
func (s *EST) hasAuthWebhooks() bool {
	return s.challengeValidationController != nil && len(s.challengeValidationController.webhooks) > 0
}

// normalizeAuthConfig applies defaults and validates auth configuration.
func (s *EST) normalizeAuthConfig() error {
	enable := true
	if !s.authMethodsConfigured() {
		s.EnableHTTPBasicAuth = &enable
	}
	if s.EnableHTTPBasicAuth == nil && (s.BasicAuthUsername != "" || s.BasicAuthPassword != "") {
		s.EnableHTTPBasicAuth = &enable
	}
	if boolValue(s.EnableHTTPBasicAuth, false) && s.BasicAuthPassword == "" && !s.hasAuthWebhooks() {
		return errors.New("basic auth password cannot be empty")
	}
	return nil
}

// authMethodsConfigured reports whether any auth method is explicitly configured.
func (s *EST) authMethodsConfigured() bool {
	return s.EnableTLSClientCertificate != nil ||
		s.hasClientCertificateRoots() ||
		s.EnableHTTPBasicAuth != nil
}

// parseClientCertificateRoots loads external client certificate roots.
func (s *EST) parseClientCertificateRoots() error {
	if len(s.ClientCertificateRoots) == 0 {
		return nil
	}
	var (
		block   *pem.Block
		hasCert bool
		rest    = s.ClientCertificateRoots
	)
	s.clientCertificateRootPool = x509.NewCertPool()
	for rest != nil {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.New("error parsing clientCertificateRoots: malformed certificate")
		}
		s.clientCertificateRootPool.AddCert(cert)
		hasCert = true
	}
	if !hasCert {
		return errors.New("error parsing clientCertificateRoots: no certificates found")
	}
	return nil
}

func (s *EST) hasClientCertificateRoots() bool {
	return len(s.ClientCertificateRoots) > 0
}

// verifyCertificate validates the client certificate against CA roots.
func verifyCertificate(cert *x509.Certificate, chain, roots, intermediates []*x509.Certificate) error {
	rootPool := x509.NewCertPool()
	for _, root := range roots {
		if root != nil {
			rootPool.AddCert(root)
		}
	}
	intermediatePool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		if intermediate != nil {
			intermediatePool.AddCert(intermediate)
		}
	}
	return verifyCertificateWithPool(cert, chain, rootPool, intermediatePool)
}

// verifyCertificateWithPool validates the client certificate using explicit pools.
func verifyCertificateWithPool(cert *x509.Certificate, chain []*x509.Certificate, roots, intermediates *x509.CertPool) error {
	if intermediates == nil {
		intermediates = x509.NewCertPool()
	}
	for i, intermediate := range chain {
		if i == 0 || intermediate == nil {
			continue
		}
		intermediates.AddCert(intermediate)
	}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("invalid client certificate: %w", err)
	}
	return nil
}

// boolValue returns the dereferenced value or a default.
func boolValue(value *bool, defaultValue bool) bool {
	if value == nil {
		return defaultValue
	}
	return *value
}

// subtleCompare compares secrets in constant time.
func subtleCompare(expected, actual string) bool {
	if len(expected) != len(actual) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}
