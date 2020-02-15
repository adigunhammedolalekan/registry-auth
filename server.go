package registry

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/docker/distribution/registry/auth/token"
	"github.com/docker/libtrust"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

const signAuth = "AUTH"
// AuthServer is the token authentication server
type AuthServer struct {
	authorizer    Authorizer
	authenticator Authenticator
	privateKey    libtrust.PrivateKey
	pubKey        libtrust.PublicKey
	tokenOpt      *TokenOption
}

// NewAuthServer creates a new AuthServer
func NewAuthServer(opt *Option) (*AuthServer, error) {
	if opt.Authenticator == nil {
		opt.Authenticator = &DefaultAuthenticator{}
	}
	if opt.Authorizer == nil {
		opt.Authorizer = &DefaultAuthorizer{}
	}
	pb, prk, err := loadCertAndKey(opt.Certfile, opt.Keyfile)
	if err != nil {
		return nil, err
	}
	tk := &TokenOption{Expire: opt.TokenExpiration, Issuer: opt.TokenIssuer}
	return &AuthServer{
		pubKey: pb, privateKey: prk, authenticator: opt.Authenticator,
		authorizer: opt.Authorizer, tokenOpt: tk,
	}, nil
}

func (srv *AuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// grab user's auth parameters
	username, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := srv.authenticator.Authenticate(username, password); err != nil {
		http.Error(w, "unauthorized: invalid auth credentials", http.StatusUnauthorized)
		return
	}
	req := srv.parseRequest(r)
	actions, err := srv.authorizer.Authorize(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	// create token for this user using the actions returned
	// from the authorization check
	tk, err := srv.createToken(req, actions)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	srv.ok(w, tk)
}

func (srv *AuthServer) createToken(req *AuthorizationRequest, actions []string) (*Token, error) {
	// sign any string to get the used signing Algorithm for the private key
	_, algo, err := srv.privateKey.Sign(strings.NewReader(signAuth), 0)
	if err != nil {
		return nil, err
	}
	header := token.Header{
		Type:       "JWT",
		SigningAlg: algo,
		KeyID:      srv.pubKey.KeyID(),
	}
	headerJson, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	claim := token.ClaimSet{
		Issuer:     srv.tokenOpt.Issuer,
		Subject:    req.Account,
		Audience:   req.Service,
		Expiration: now + srv.tokenOpt.Expire,
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
	sig, sigAlgo, err := srv.privateKey.Sign(strings.NewReader(payload), 0)
	if err != nil && sigAlgo != algo {
		return nil, err
	}
	tk := fmt.Sprintf("%s%s%s", payload, token.TokenSeparator, encodeBase64(sig))
	return &Token{Token: tk, AccessToken: tk}, nil
}

func (srv *AuthServer) parseRequest(r *http.Request) *AuthorizationRequest {
	q := r.URL.Query()
	req := &AuthorizationRequest{
		Service: q.Get("service"),
		Account: q.Get("account"),
	}
	parts := strings.Split(r.URL.Query().Get("scope"), ":")
	if len(parts) > 0 {
		req.Type = parts[0]
	}
	if len(parts) > 1 {
		req.Name = parts[1]
	}
	if len(parts) > 2 {
		req.Actions = strings.Split(parts[2], ",")
	}
	if req.Account == "" {
		req.Account = req.Name
	}
	return req
}

func (srv *AuthServer) ok(w http.ResponseWriter, tk *Token) {
	data, _ := json.Marshal(tk)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func encodeBase64(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
