package main

import (
	"net/http"
)

func Proxy(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("url")
	// GOAST-SSRF-001: tainted URL in http.Get()
	resp, _ := http.Get(url)
	_ = resp
	_ = w
}
