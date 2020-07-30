package main

import (
	"errors"
	registry "github.com/adigunhammedolalekan/registry-auth"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	crt, key := "/mnt/certs/RootCA.crt", "/mnt/certs/RootCA.key"
	opt := &registry.Option{
		Certfile:        "/mnt/certs/RootCA.crt",
		Keyfile:         "/mnt/certs/RootCA.key",
		TokenExpiration: time.Now().Add(24 * time.Hour).Unix(),
		TokenIssuer:     "Authz",
		Authenticator:   &httpAuthenticator{},
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

type httpAuthenticator struct {
}

func (h *httpAuthenticator) Authenticate(username, password string) error {
	if username != "adigun" {
		return errors.New("error")
	}
	return nil
}
