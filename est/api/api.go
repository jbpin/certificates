// Package api implements an EST HTTP server.
package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/smallstep/pkcs7"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/api/log"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/est"
)

const (
	maxPayloadSize = 2 << 20
)

// Route configures the EST routes under the provided router.
func Route(r api.Router) {
	// Well-known endpoints with provisioner path parameter.
	r.MethodFunc(http.MethodGet, "/.well-known/est/{provisionerName}/cacerts", getCACerts)
	r.MethodFunc(http.MethodGet, "/.well-known/est/{provisionerName}/csrattrs", getCSRAttrs)
	r.MethodFunc(http.MethodPost, "/.well-known/est/{provisionerName}/simpleenroll", enroll)
	r.MethodFunc(http.MethodPost, "/.well-known/est/{provisionerName}/simplereenroll", enroll)

	// Alternate EST prefix.
	r.MethodFunc(http.MethodGet, "/est/{provisionerName}/cacerts", getCACerts)
	r.MethodFunc(http.MethodGet, "/est/{provisionerName}/csrattrs", getCSRAttrs)
	r.MethodFunc(http.MethodPost, "/est/{provisionerName}/simpleenroll", enroll)
	r.MethodFunc(http.MethodPost, "/est/{provisionerName}/simplereenroll", enroll)
}

func lookupProvisioner(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "provisionerName")
		if name == "" || name == "/" {
			name = r.URL.Query().Get("provisioner")
		}
		if name == "" {
			fail(w, r, errors.New("missing provisioner name"))
			return
		}
		provisionerName, err := url.PathUnescape(name)
		if err != nil {
			fail(w, r, fmt.Errorf("error url unescaping provisioner name '%s'", name))
			return
		}

		ctx := r.Context()
		auth := authority.MustFromContext(ctx)
		p, err := auth.LoadProvisionerByName(provisionerName)
		if err != nil {
			fail(w, r, err)
			return
		}

		prov, ok := p.(*provisioner.EST)
		if !ok {
			fail(w, r, errors.New("provisioner must be of type EST"))
			return
		}

		ctx = est.NewProvisionerContext(ctx, est.Provisioner(prov))
		next(w, r.WithContext(ctx))
	}
}

func getCACerts(w http.ResponseWriter, r *http.Request) {
	lookupProvisioner(getCACertsHandler)(w, r)
}

func getCACertsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	auth := est.MustFromContext(ctx)

	certs, err := auth.GetCACertificates(ctx)
	if err != nil {
		fail(w, r, fmt.Errorf("failed to get CA certificates: %w", err))
		return
	}

	data, err := auth.BuildSignedChain(ctx, certs)
	if err != nil {
		fail(w, r, fmt.Errorf("failed to encode CA certificates: %w", err))
		return
	}

	writeResponse(w, r, data, "application/pkcs7-mime; smime-type=certs-only", http.StatusOK)
}

func getCSRAttrs(w http.ResponseWriter, r *http.Request) {
	lookupProvisioner(getCSRAttrsHandler)(w, r)
}

func getCSRAttrsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov := est.ProvisionerFromContext(ctx)

	attrs, err := prov.GetCSRAttributes(ctx)
	if err != nil {
		fail(w, r, fmt.Errorf("failed to get CSR attributes: %w", err))
		return
	}
	if attrs == nil {
		attrs = []byte{}
	}
	// Minimal implementation: allow provisioner to return nil/empty for "no attributes".
	writeResponse(w, r, attrs, "application/csrattrs", http.StatusOK)
}

func enroll(w http.ResponseWriter, r *http.Request) {
	lookupProvisioner(enrollHandler)(w, r)
}

func enrollHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	auth := est.MustFromContext(ctx)
	// prov := est.ProvisionerFromContext(ctx)

	secret, err := basicAuthSecret(r)
	if err != nil {
		failWithStatus(w, r, http.StatusUnauthorized, err)
		return
	}

	if err := auth.ValidateChallenge(ctx, secret); err != nil {
		failWithStatus(w, r, http.StatusUnauthorized, fmt.Errorf("invalid credentials: %w", err))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxPayloadSize))
	if err != nil {
		failWithStatus(w, r, http.StatusBadRequest, fmt.Errorf("failed reading request body: %w", err))
		return
	}

	csr, err := parseCSR(body)
	if err != nil {
		failWithStatus(w, r, http.StatusBadRequest, fmt.Errorf("failed parsing CSR: %w", err))
		return
	}
	if err := csr.CheckSignature(); err != nil {
		failWithStatus(w, r, http.StatusBadRequest, fmt.Errorf("invalid CSR signature: %w", err))
		return
	}

	certChain, err := auth.SignCSR(ctx, csr)
	if err != nil {
		failWithStatus(w, r, http.StatusInternalServerError, fmt.Errorf("failed issuing certificate: %w", err))
		return
	}

	signed, err := auth.BuildSignedChain(ctx, certChain)
	if err != nil {
		failWithStatus(w, r, http.StatusInternalServerError, fmt.Errorf("failed encoding certificate: %w", err))
		return
	}

	writeResponse(w, r, signed, "application/pkcs7-mime; smime-type=certs-only", http.StatusOK)
}

func basicAuthSecret(r *http.Request) (string, error) {
	username, password, ok := r.BasicAuth()
	_ = username // username is not used in this minimal auth scheme
	if !ok {
		return "", errors.New("missing basic auth")
	}
	if password == "" {
		return "", errors.New("empty basic auth password")
	}
	return password, nil
}

func parseCSR(body []byte) (*x509.CertificateRequest, error) {
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}

	// Try PEM first.
	if b, _ := pem.Decode(body); b != nil {
		return x509.ParseCertificateRequest(b.Bytes)
	}

	// Try raw CSR DER.
	if csr, err := x509.ParseCertificateRequest(body); err == nil {
		return csr, nil
	}

	// Try PKCS7 wrapping.
	if p7, err := pkcs7.Parse(body); err == nil {
		if len(p7.Content) == 0 {
			return nil, errors.New("pkcs7 message missing content")
		}
		return x509.ParseCertificateRequest(p7.Content)
	}

	return nil, errors.New("unable to parse CSR")
}

func writeResponse(w http.ResponseWriter, r *http.Request, data []byte, contentType string, status int) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(status)

	encoder := base64.NewEncoder(base64.StdEncoding, w)
	_, _ = encoder.Write(data)
	_ = encoder.Close()
}

func fail(w http.ResponseWriter, r *http.Request, err error) {
	log.Error(w, r, err)
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func failWithStatus(w http.ResponseWriter, r *http.Request, status int, err error) {
	log.Error(w, r, err)
	http.Error(w, err.Error(), status)
}
