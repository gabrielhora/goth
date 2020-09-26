package goth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestGoth(path string, roles ...string) (http.Handler, *Goth) {
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, req *http.Request) {
		_, _ = fmt.Fprint(w, "hello world")
	})
	auth := func(req *http.Request) (interface{}, []string, error) {
		return 1, roles, nil
	}
	g := New(mux, auth)
	return mux, g
}

func TestSimpleRules(t *testing.T) {
	tt := []struct {
		user               interface{}
		roles              []string
		rule               string
		expectedStatusCode int
	}{
		{
			user:               1,
			roles:              nil,
			rule:               "deny",
			expectedStatusCode: 403,
		},
		{
			user:               1,
			roles:              nil,
			rule:               "allow",
			expectedStatusCode: 200,
		},
		{
			user:               nil,
			roles:              nil,
			rule:               "allow",
			expectedStatusCode: 401,
		},
		{
			user:               nil,
			roles:              nil,
			rule:               "annon",
			expectedStatusCode: 200,
		},
		{
			user:               1,
			roles:              []string{"admin"},
			rule:               "user",
			expectedStatusCode: 403,
		},
		{
			user:               1,
			roles:              []string{"admin", "superuser"},
			rule:               "admin",
			expectedStatusCode: 200,
		},
		{
			user:               1,
			roles:              []string{"admin"},
			rule:               "role1,role2,admin,role3",
			expectedStatusCode: 200,
		},
		{
			user:               1,
			roles:              []string{"admin"},
			rule:               "role1,role2,role3",
			expectedStatusCode: 403,
		},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("user=%v/roles=%v/rule=%s", tc.user, tc.roles, tc.rule), func(t *testing.T) {
			// setup
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
				_, _ = fmt.Fprint(w, "hello world")
			})
			auth := func(req *http.Request) (interface{}, []string, error) {
				return tc.user, tc.roles, nil
			}
			g := New(mux, auth)
			g.Rule("/", tc.rule)

			// request
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			g.ServeHTTP(w, req)
			resp := w.Result()

			// check
			if resp.StatusCode != tc.expectedStatusCode {
				t.Fatalf("expected status %d, got %d", tc.expectedStatusCode, resp.StatusCode)
			}
		})
	}
}

func TestAllowWhenMissing(t *testing.T) {
	_, g := newTestGoth("/")
	g.AllowMissing(true)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	resp := w.Result()

	if resp.StatusCode != 200 {
		t.Errorf("expected status code 200, got %d", resp.StatusCode)
	}
}
