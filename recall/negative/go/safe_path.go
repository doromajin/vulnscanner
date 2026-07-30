package main

import (
	"net/http"
	"os"
)

func SafeServe(w http.ResponseWriter, r *http.Request) {
	// Safe: hardcoded path, no user input reaches os.Open
	f, _ := os.Open("/var/www/static/index.html")
	_ = f
	_ = w
	_ = r
}
