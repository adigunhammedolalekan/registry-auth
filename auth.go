package registry

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/docker/distribution/registry/auth/token"
	"github.com/docker/libtrust"
	"math/rand"
	"strings"
	"time"
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
// TokenGenerator: an implementation should create a valid JWT according to the spec here
// https://github.com/docker/distribution/blob/1b9ab303a477ded9bdd3fc97e9119fa8f9e58fca/docs/spec/auth/jwt.md
// a default implementation that follows the spec is used when it is not provided
type TokenGenerator interface {
	Generate(req *AuthorizationRequest, actions []string) (*Token, error)
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

type tokenGenerator struct {
	privateKey libtrust.PrivateKey
	pubKey     libtrust.PublicKey
	tokenOpt   *TokenOption
}

func newTokenGenerator(pk libtrust.PublicKey, prk libtrust.PrivateKey, opt *TokenOption) TokenGenerator {
	return &tokenGenerator{pubKey: pk, privateKey: prk, tokenOpt: opt}
}

func (tg *tokenGenerator) Generate(req *AuthorizationRequest, actions []string) (*Token, error) {
	// sign any string to get the used signing Algorithm for the private key
	_, algo, err := tg.privateKey.Sign(strings.NewReader(signAuth), 0)
	if err != nil {
		return nil, err
	}
	header := token.Header{
		Type:       "JWT",
		SigningAlg: algo,
		KeyID:      tg.pubKey.KeyID(),
	}
	headerJson, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	claim := token.ClaimSet{
		Issuer:     tg.tokenOpt.Issuer,
		Subject:    req.Account,
		Audience:   req.Service,
		Expiration: now + tg.tokenOpt.Expire,
		NotBefore:  now - 10,
		IssuedAt:   now,
		JWTID:      fmt.Sprintf("%d", rand.Int63()),
		Access:     []*token.ResourceActions{},
	}
	claim.Access = append(claim.Access, &token.ResourceActions{
		Type:    req.Type,
		Name:    req.Name,
		Actions: actions,
	})
	claimJson, err := json.Marshal(claim)
	if err != nil {
		return nil, err
	}
	payload := fmt.Sprintf("%s%s%s", encodeBase64(headerJson), token.TokenSeparator, encodeBase64(claimJson))
	sig, sigAlgo, err := tg.privateKey.Sign(strings.NewReader(payload), 0)
	if err != nil && sigAlgo != algo {
		return nil, err
	}
	tk := fmt.Sprintf("%s%s%s", payload, token.TokenSeparator, encodeBase64(sig))
	return &Token{Token: tk, AccessToken: tk}, nil
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
