package provisioner

import (
	"context"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"time"

	"github.com/pkg/errors"

	"github.com/smallstep/linkedca"
)

// EST is the EST provisioner type, an entity that can authorize the EST flow.
type EST struct {
	*base
	ID                       string   `json:"-"`
	Type                     string   `json:"type"`
	Name                     string   `json:"name"`
	Secret                   string   `json:"secret,omitempty"`
	ForceCN                  bool     `json:"forceCN,omitempty"`
	Capabilities             []string `json:"capabilities,omitempty"`
	IncludeRoot              bool     `json:"includeRoot,omitempty"`
	ExcludeIntermediate      bool     `json:"excludeIntermediate,omitempty"`
	MinimumPublicKeyLength   int      `json:"minimumPublicKeyLength,omitempty"`
	CSRAttrs                 []byte   `json:"csrAttrs,omitempty"`
	Options                  *Options `json:"options,omitempty"`
	Claims                   *Claims  `json:"claims,omitempty"`
	ctl                      *Controller
	signer                   crypto.Signer
	signerCertificate        *x509.Certificate
	notificationController   *notificationController
	challengeValidationMutex struct{}
}

// GetID returns the provisioner unique identifier.
func (s *EST) GetID() string {
	if s.ID != "" {
		return s.ID
	}
	return s.GetIDForToken()
}

// GetIDForToken returns an identifier that will be used to load the provisioner from a token.
func (s *EST) GetIDForToken() string {
	return "est/" + s.Name
}

// GetName returns the name of the provisioner.
func (s *EST) GetName() string {
	return s.Name
}

// GetType returns the type of provisioner.
func (s *EST) GetType() Type {
	return TypeEST
}

// GetEncryptedKey returns the base provisioner encrypted key if it's defined.
func (s *EST) GetEncryptedKey() (string, string, bool) {
	return "", "", false
}

// GetTokenID returns the identifier of the token. This provisioner does not support tokens.
func (s *EST) GetTokenID(string) (string, error) {
	return "", ErrTokenFlowNotSupported
}

// GetOptions returns the configured provisioner options.
func (s *EST) GetOptions() *Options {
	return s.Options
}

// DefaultTLSCertDuration returns the default TLS cert duration enforced by the provisioner.
func (s *EST) DefaultTLSCertDuration() time.Duration {
	return s.ctl.Claimer.DefaultTLSCertDuration()
}

// Init initializes and validates the fields of an EST type.
func (s *EST) Init(config Config) (err error) {
	switch {
	case s.Type == "":
		return errors.New("provisioner type cannot be empty")
	case s.Name == "":
		return errors.New("provisioner name cannot be empty")
	}

	if s.MinimumPublicKeyLength == 0 {
		s.MinimumPublicKeyLength = 2048
	}
	if s.MinimumPublicKeyLength%8 != 0 {
		return errors.Errorf("%d bits is not exactly divisible by 8", s.MinimumPublicKeyLength)
	}

	// Only static shared secret auth in the first iteration.
	if s.Secret == "" {
		return errors.New("provisioner secret cannot be empty")
	}

	s.ctl, err = NewController(s, s.Claims, config, s.Options)
	return err
}

// AuthorizeSign does not do any verification beyond the shared secret; main validation is in the EST protocol.
func (s *EST) AuthorizeSign(context.Context, string) ([]SignOption, error) {
	return []SignOption{
		s,
		newProvisionerExtensionOption(TypeEST, s.Name, "").WithControllerOptions(s.ctl),
		newForceCNOption(s.ForceCN),
		profileDefaultDuration(s.ctl.Claimer.DefaultTLSCertDuration()),
		newPublicKeyMinimumLengthValidator(s.MinimumPublicKeyLength),
		newValidityValidator(s.ctl.Claimer.MinTLSCertDuration(), s.ctl.Claimer.MaxTLSCertDuration()),
		newX509NamePolicyValidator(s.ctl.getPolicy().getX509()),
		s.ctl.newWebhookController(nil, linkedca.Webhook_X509),
	}, nil
}

// ShouldIncludeRootInChain indicates if the CA should return its root in the chain.
func (s *EST) ShouldIncludeRootInChain() bool {
	return s.IncludeRoot
}

// ShouldIncludeIntermediateInChain indicates if the CA should include the intermediate CA certificate.
func (s *EST) ShouldIncludeIntermediateInChain() bool {
	return !s.ExcludeIntermediate
}

// GetSigner returns the provisioner specific signer, used to sign EST responses.
func (s *EST) GetSigner() (*x509.Certificate, crypto.Signer) {
	return s.signerCertificate, s.signer
}

// ValidateSharedSecret checks the provided secret against the configured static secret.
func (s *EST) ValidateSharedSecret(_ context.Context, secret string) error {
	if subtle.ConstantTimeCompare([]byte(s.Secret), []byte(secret)) == 0 {
		return errors.New("invalid shared secret")
	}
	return nil
}

// GetCSRAttributes returns the CSR attributes to signal to clients.
func (s *EST) GetCSRAttributes(context.Context) ([]byte, error) {
	return s.CSRAttrs, nil
}
