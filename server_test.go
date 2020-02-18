package registry

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

var mockToken = &Token{Token: "token", AccessToken: "token"}

type mockTokenGenerator struct {
	t   *Token
	err error
}

func newMockTokenGenerator(t *Token, err error) *mockTokenGenerator {
	return &mockTokenGenerator{t: t, err: err}
}
func (t *mockTokenGenerator) Generate(req *AuthorizationRequest, actions []string) (*Token, error) {
	return t.t, t.err
}

type mockAuthenticator struct {
	username, password string
}

func newMockAuthenticator(u, p string) *mockAuthenticator {
	return &mockAuthenticator{username: u, password: p}
}

func (a *mockAuthenticator) Authenticate(username, password string) error {
	if a.username != username || a.password != password {
		return errors.New("invalid login")
	}
	return nil
}

type mockAuthorizer struct {
	perms []string
}

func newMockAuthorizer(p []string) *mockAuthorizer {
	return &mockAuthorizer{perms: p}
}

func (a *mockAuthorizer) Authorize(req *AuthorizationRequest) ([]string, error) {
	return a.perms, nil
}

func TestNewAuthServerServe(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.RequestURI = "token?service=registry.docker.io&scope=repository:samalba/my-app:pull,push"
	r.SetBasicAuth("foo", "bar")

	srv := &AuthServer{
		tokenGenerator: newMockTokenGenerator(mockToken, nil),
		authorizer:     newMockAuthorizer([]string{"pull", "push"}),
		authenticator:  newMockAuthenticator("foo", "bar"),
	}
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status code %d; got %d", http.StatusOK, w.Code)
	}
}

func TestAuthServer_ServeHTTPAuthError(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.RequestURI = "token?service=registry.docker.io&scope=repository:samalba/my-app:pull,push"
	r.SetBasicAuth("foo", "barr")

	srv := &AuthServer{
		tokenGenerator: &mockTokenGenerator{},
		authorizer:     newMockAuthorizer([]string{"pull", "push"}),
		authenticator:  newMockAuthenticator("foo", "bar"),
	}
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status code %d; got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAuthServer_ServeHTTPTokenError(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.RequestURI = "token?service=registry.docker.io&scope=repository:samalba/my-app:pull,push"
	r.SetBasicAuth("foo", "bar")

	srv := &AuthServer{
		tokenGenerator: newMockTokenGenerator(nil, errors.New("fake token error")),
		authorizer:     newMockAuthorizer([]string{"pull", "push"}),
		authenticator:  newMockAuthenticator("foo", "bar"),
	}
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status code %d; got %d", http.StatusInternalServerError, w.Code)
	}
}
