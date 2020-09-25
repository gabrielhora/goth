package main

import (
	"fmt"
	"github.com/gabrielhora/goth"
	"net/http"
)

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
	g.Rule("/admin/?(.*)", "admin")
	g.Rule("/?(.*)", "annon")

	server := http.Server{
		Addr:    ":8080",
		Handler: g,
	}

	_ = server.ListenAndServe()
}

func auth(req *http.Request) (interface{}, []string, error) {
	return 1, []string{"user"}, nil
}
