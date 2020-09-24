package goth

import (
	"log"
	"net/http"
	"regexp"
	"strings"
)

type AuthorizerFunc func(req *http.Request) (user interface{}, roles []string, err error)

type urlPattern struct {
	pattern     string
	regex       *regexp.Regexp
	specificity int
}

type urlRule struct {
	roles []string
	allow bool
	deny  bool
	annon bool
}

type Goth struct {
	// Function that will determine the current user and it's roles
	authorizer AuthorizerFunc

	// The URL path that will be used to redirect unauthenticated/unauthorized users
	loginPath string

	// Underlying handler being wrapped
	handler http.Handler

	// Map from url pattern to rule string
	rules map[*urlPattern]*urlRule

	// Determine if requests to undefined paths will be allowed or denied
	allowMissing bool
}

type Opts func(*Goth)

func New(opts ...Opts) Goth {
	g := Goth{
		rules:        map[*urlPattern]*urlRule{},
		allowMissing: false,
	}
	for _, opts := range opts {
		opts(&g)
	}
	return g
}

func (g Goth) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	g.handler.ServeHTTP(w, req)
}

// AuthorizeFunc returns the user as an interface type, a list of the user's roles and  an optional
// error. If user is nil the user will be considered authenticated and will  only be allowed to
// access "annon" paths. The list of roles are simple strings that are matched (case sensitive) when
// defining authorization rules. If an error is returned by this function, it will be logged to
// strerr and a HTTP 500 response will be sent.
func Authorizer(af AuthorizerFunc) Opts {
	return func(g *Goth) {
		g.authorizer = af
	}
}

// Rule adds a new matching rule for a URL pattern.
//
// The pattern is any valid regular expression. It will be compiled when defining the rule and any
// errors will result in a panic.
//
// The following rules are allowed:
//
//   - list of roles (ex: admin,user): any of the specified role will be allowed
//   - "allow": all requests will be allowed regardless of users roles, but the user
//              needs to be authenticated
//   - "annon": any requests will be allowed even for unauthenticated users
//   - "deny": deny all requests
//
// If multiple rules are matched for one request, the more restrictive pattern will be honored,
// which means there is a precedence order of the rules:
//
//   deny > list of roles > allow > annon
//
// Also always the most specific pattern will be applied. For example, given the rules:
//
//   Rule("/admin/users/?(.*?)", "admin")
//   Rule("/admin/?(.*?)", "allow")
//
// When accessing path "/admin/users/123" both rules would match, but the first one will be
// applied because it is more specific to the "/admin/users" segment.
// The specificity of the pattern is determined by the number of forward slashes "/" in it, the more
// it have the more specific it is considered.
func Rule(pattern, rule string) Opts {
	return func(g *Goth) {
		r, err := regexp.Compile(pattern)
		if err != nil {
			log.Fatalf("invalid regular expressiong %s: %v", pattern, err)
		}
		urlP := &urlPattern{
			pattern:     pattern,
			regex:       r,
			specificity: strings.Count(pattern, "/"),
		}

		urlR := &urlRule{}
		switch rule {
		case "allow":
			urlR.allow = true
		case "deny":
			urlR.deny = true
		case "annon":
			urlR.annon = true
		default:
			urlR.roles = strings.Split(rule, ",")
		}

		g.rules[urlP] = urlR
	}
}

// LoginPath sets the URL path that will be used to redirect unauthenticated/unauthorized users. If
// the login path is not set, an HTTP 401 (unauthorized) or 403 (forbidden) response will be
// returned (depending if the Authorizer function returns a user or not).
func LoginPath(path string) Opts {
	return func(g *Goth) {
		g.loginPath = path
	}
}

// Handler sets the underlying http.Handler that will be wrapped
func Handler(h http.Handler) Opts {
	return func(g *Goth) {
		g.handler = h
	}
}

// AllowMissing will allow requests to undefined patterns to go through. The default behaviour is
// to deny all requests to undefined paths.
func AllowMissing(g *Goth) {
	g.allowMissing = true
}

func server() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", index)

	g := New(
		Handler(mux),
		Authorizer(auth),
		LoginPath("/login"),
		Rule("/admin/**", "admin"),
	)

	server := http.Server{
		Addr:    ":8080",
		Handler: g,
	}

	_ = server.ListenAndServe()
}

func auth(req *http.Request) (interface{}, []string, error) {
	return 1, []string{"admin"}, nil
}

func index(w http.ResponseWriter, req *http.Request) {}
