# Goth (wip)

Centrally define authorization rules for your HTTP handlers.

Example:

```go
func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
        _, _ = fmt.Fprint(w, "index")
    })

    mux.HandleFunc("/admin/", func(w http.ResponseWriter, req *http.Request) {
        _, _ = fmt.Fprint(w, "admin")
    })

    mux.HandleFunc("/login", func(w http.ResponseWriter, req *http.Request) {
        _, _ = fmt.Fprint(w, "login")
    })

    g := goth.New(mux, auth)
    g.LoginURL("/login")
    
    // anything inside /admin requires "admin" or "staff" roles
    g.Rule("/admin/?(.*)", "admin,staff")
    
    // anything else allow any user
    g.Rule("/?(.*)", "annon")

    server := http.Server{
        Addr:    ":8080",
        Handler: g,
    }

    _ = server.ListenAndServe()
}

// this function should return the current user and it's roles, you are
// free to choose how to get this info (from session, cookie, header, etc)
func auth(req *http.Request) (user interface{}, roles []string, err error) {
    return 1, []string{"user"}, nil
}
``` 
