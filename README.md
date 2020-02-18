## registry-auth
a package to implements docker registry token authentication server as described here [https://github.com/docker/distribution/blob/1b9ab303a477ded9bdd3fc97e9119fa8f9e58fca/docs/spec/auth/index.md]

The goal of this project is to provide a flexible, easy-to-customize package for implementing `docker registry token authentication server`. Other solutions allows developers to configure `auth database` or `acls` which is too simple and complex at the same time. 
This package will allow developers to perform authentication and authorization to private/self-hosted `docker registry` in-app, which makes it easy for developers to write their authentication or authorization logic as they see fit.

This package is particularly useful when you have a self-hosted docker registry and you need to define access and permissions for users. Default docker registry login is a simple `htpasswd` file that'll be verified over HTTP basic auth. This method limited as it only allows a single user a full access to the docker registry. By having a token authentication server, you can write your own authentication and authorization logic thereby allowing multiple
user authentication for your self-hosted `docker-registry`

### Usage

You need a `registry.Option{}` to configure a valid authentication server. Find below the available options and their function
```go
// Option is the registry token authorization server configuration options
type Option struct {
	// an Authorizer implementation to authorize registry users
	Authorizer Authorizer
	// an Authenticator implementation to authenticate registry users
	Authenticator Authenticator
	// a pluggable tokenGenerator
	TokenGenerator TokenGenerator
	// .crt & .key file to sign JWTs and also start an https server
	Certfile string
	Keyfile  string
	// token expiration time
	TokenExpiration int64
	// token issuer specified in docker registry configuration file
	TokenIssuer string
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

func main() {
    crt, key := "/mnt/certs/RootCA.crt", "/mnt/certs/RootCA.key"
    opt := &registry.Option{
        Certfile:        crt,
        Keyfile:         key,
        TokenExpiration: time.Now().Add(24 * time.Hour).Unix(), // 24hrs
        TokenIssuer:     "Authz",
        Authenticator:   &exampleAuthenticator{}, // could be nil, meaning all users would be authenticated by default
    }
    srv, err := registry.NewAuthServer(opt)
    if err != nil {
        log.Fatal(err)
    }
    addr := ":" + os.Getenv("PORT")
    http.Handle("/auth", srv)
    log.Println("Server running at ", addr)
    if err := http.ListenAndServeTLS(addr, crt, key, nil); err != nil {
        log.Fatal(err)
    }
    // or use srv.Run(":PORT")
    // where :PORT is your desired port, this will listen for auth request on endpoint `/`.
    if err := srv.Run(":5011"); err != nil {
        log.Fatal(err)
    }
}

type exampleAuthenticator struct{} 
func (a *exampleAuthenticator) Authenticate(username, password string) error {
    // here, you want to compare username and password against your record
    // then determine whether to return error or not
    if username && password is valid {
        return nil
    }
    return errors.New("invalid credentials")
}
```