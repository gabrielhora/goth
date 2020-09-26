package goth

/*
todo:
  - add callback for when not authorized
*/

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type contextKey int

const (
	userKey  = contextKey(1)
	rolesKey = contextKey(2)
)

// AuthorizeFunc returns the user as an interface type, a list of the user's roles and  an optional
// error. If user is nil the user will be considered authenticated and will  only be allowed to
// access "annon" paths. The list of roles are simple strings that are matched (case sensitive) when
// defining authorization rules. If an error is returned by this function, it will be logged to
// strerr and a HTTP 500 response will be sent.
type AuthorizerFunc func(req *http.Request) (user interface{}, roles []string, err error)

type urlRule struct {
	// regex to match against URL path
	regex *regexp.Regexp

	// allow users that have these one of the roles
	roles []string

	// allow any authenticated user
	allow bool

	// deny all access
	deny bool

	// allow any user regardless of authentication
	annon bool
}

type Goth struct {
	// Function that will determine the current user and it's roles
	authorizer AuthorizerFunc

	// The URL path that will be used to redirect unauthenticated/unauthorized users
	loginURL *url.URL

	// Underlying handler being wrapped
	handler http.Handler

	// Slice of defined rules
	rules []urlRule

	// Determine if requests to undefined paths will be allowed or denied
	allowMissing bool
}

// HasRole checks if the current user have one of the roles
func HasRole(req *http.Request, role ...string) bool {
	userRoles, ok := req.Context().Value(rolesKey).([]string)
	if !ok {
		return false
	}
	return checkUserHasRole(role, userRoles)
}

// CurrentUser gets the user returned from the AuthorizerFunc from the request context
func CurrentUser(req *http.Request) interface{} {
	return req.Context().Value(userKey)
}

// New creates a new Goth instance.
func New(handler http.Handler, authorizer AuthorizerFunc) *Goth {
	return &Goth{
		authorizer:   authorizer,
		handler:      handler,
		rules:        []urlRule{},
		allowMissing: false,
	}
}

func (g *Goth) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path

	// if this is a request to the loginPath we should allow it
	if g.loginURL != nil && path == g.loginURL.Path {
		g.handler.ServeHTTP(w, req)
		return
	}

	user, userRoles, err := g.authorizer(req)
	if err != nil {
		log.Printf("error authorizing user: %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// add user and roles to request context
	ctx := context.WithValue(req.Context(), userKey, user)
	ctx = context.WithValue(ctx, rolesKey, userRoles)
	req = req.WithContext(ctx)

	// match the request with defined rules
	ruleFound := false
	var rule urlRule
	for i := 0; i < len(g.rules); i++ {
		rule = g.rules[i]
		if rule.regex.MatchString(path) {
			ruleFound = true
			break
		}
	}

	// no rules were found for this path and we are configured to allow missing paths
	if !ruleFound && g.allowMissing {
		g.handler.ServeHTTP(w, req)
		return
	}

	// send appropriate http status if no rules are found
	if !ruleFound {
		g.denyRequest(w, req, user)
		return
	}

	// apply the selected rule
	switch {
	case rule.deny:
		g.denyRequest(w, req, user)
	case rule.allow && user == nil:
		g.denyRequest(w, req, user)
	case rule.annon:
		g.handler.ServeHTTP(w, req)
	case len(rule.roles) > 0:
		if checkUserHasRole(rule.roles, userRoles) {
			g.handler.ServeHTTP(w, req)
		} else {
			g.denyRequest(w, req, user)
		}
	default:
		g.denyRequest(w, req, user)
	}
}

// checkUserHasRole checks if the user have at least one of the rule's role
func checkUserHasRole(ruleRoles, userRoles []string) bool {
	for _, role1 := range ruleRoles {
		for _, role2 := range userRoles {
			if role1 == role2 {
				return true
			}
		}
	}
	return false
}

// denyRequest sends the appropriate denial http response back to the user
func (g *Goth) denyRequest(w http.ResponseWriter, req *http.Request, user interface{}) {
	log.Printf("Request to %s denied to user %v", req.URL, user)
	if g.loginURL != nil {
		http.Redirect(w, req, g.loginURL.String(), http.StatusFound)
	} else if user == nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	} else {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
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
// Also, the order of rules are important, the rule to be applied is the first one that matches
// based on their definition order.
func (g *Goth) Rule(pattern, rule string) {
	rx, err := regexp.Compile(pattern)
	if err != nil {
		log.Fatalf("invalid regular expressiong %s: %v", pattern, err)
	}
	r := urlRule{regex: rx}
	switch rule {
	case "allow":
		r.allow = true
	case "deny":
		r.deny = true
	case "annon":
		r.annon = true
	default:
		r.roles = strings.Split(rule, ",")
	}
	g.rules = append(g.rules, r)
}

// LoginURL sets the URL path that will be used to redirect unauthenticated/unauthorized users. If
// the login path is not set, an HTTP 401 (unauthorized) or 403 (forbidden) response will be
// returned (depending if the Authorizer function returns a user or not).
func (g *Goth) LoginURL(path string) {
	if parsed, err := url.Parse(path); err != nil {
		log.Fatalf("invalid loginUrl %q: %v", path, err)
	} else {
		g.loginURL = parsed
	}
}

// AllowMissing will allow requests to undefined patterns to go through. The default behaviour is
// to deny all requests to undefined paths.
func (g *Goth) AllowMissing(value bool) {
	g.allowMissing = value
}
