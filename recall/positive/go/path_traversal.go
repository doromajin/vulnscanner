package main

import (
	"net/http"
	"os"
)

func ServeFile(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	// GOAST-PATH-001: tainted path in os.Open()
	f, _ := os.Open(filename)
	_ = f
	_ = w
}
