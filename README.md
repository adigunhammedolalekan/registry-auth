## registry-auth
a package to implements docker registry token authentication server as described here [https://github.com/docker/distribution/blob/1b9ab303a477ded9bdd3fc97e9119fa8f9e58fca/docs/spec/auth/index.md]

The goal of this project is to provide a flexible, easy-to-customize package for implementing `docker registry token authentication server`. Other solutions allows developers to configure `auth database` or `acls` which is too simple and complex at the same time. 
This package will allow developers to perform authentication and authorization to private/self-hosted `docker registry` in-app, which makes it easy for developers to write their authentication or authorization logic as they see fit.

This package is particularly useful when you have a self-hosted docker registry and you need to define access and permissions for users. Default docker registry login is a simple `htpasswd` file that'll be verified over HTTP basic auth. This method limited as it only allows a single user a full access to the docker registry. By having a token authentication server, you can write your own authentication and authorization logic thereby allowing multiple
user authentication for your self-hosted `docker-registry`

### Usage

```go
func main() {
    crt, key := "/mnt/certs/RootCA.crt", "/mnt/certs/RootCA.key"
    opt := &registry.Option{
        Certfile:        "/mnt/certs/RootCA.crt",
        Keyfile:         "/mnt/certs/RootCA.key",
        TokenExpiration: time.Now().Add(24 * time.Hour).Unix(), // 24hrs
        TokenIssuer:     "Authz",
        Authenticator:   &httpAuthenticator{}, // could be nil, meaning all users would be authenticated by default
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
}
```