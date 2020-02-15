package registry

import (
	"fmt"
	"net/url"
	"regexp"
	"testing"
)

var scopeRegex = regexp.MustCompile(`([a-z0-9]+)(\([a-z0-9]+\))?`)
func TestParseScope(t *testing.T) {
	u, err := url.Parse(fmt.Sprintf("http://localhost%s", "/auth?account=adigun&scope=repository%3Aadigun%2Fexample-auth%3Apush%2Cpull&service=Authentication"))
	if err != nil {
		t.Fatal(err)
	}
	s := u.RequestURI()
	t.Log(s)
	parts := scopeRegex.FindStringSubmatch(s)
	t.Log(parts)
}
