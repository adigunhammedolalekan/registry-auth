package registry

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/docker/libtrust"
)
// Token rep the JWT token that'll be created when authentication/authorizations succeeds
type Token struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
}

// Authenticator should be implemented to perform authentication.
// An implementation should return a non-nil error when authentication is not successful, otherwise
// a nil error should be returned
type Authenticator interface {
	Authenticate(username, password string) error
}

// Authorizer should be implemented to perform authorization.
// req.Actions should be checked against the user's authorized action on the repository,
// this function should return the list of authorized actions and a nil error. an empty list must be returned
// if requesting user is unauthorized
type Authorizer interface {
	Authorize(req *AuthorizationRequest) ([]string, error)
}
// DefaultAuthenticator makes authentication successful by default
type DefaultAuthenticator struct{}
func (d *DefaultAuthenticator) Authenticate(username, password string) error {
	return nil
}

// DefaultAuthorizer makes authorization successful by default
type DefaultAuthorizer struct{}
func (d *DefaultAuthorizer) Authorize(req *AuthorizationRequest) ([]string, error) {
	return []string{"pull", "push"}, nil
}

func loadCertAndKey(certFile, keyFile string) (libtrust.PublicKey, libtrust.PrivateKey, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	pk, err := libtrust.FromCryptoPublicKey(x509Cert.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	prk, err := libtrust.FromCryptoPrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	return pk, prk, nil
}
