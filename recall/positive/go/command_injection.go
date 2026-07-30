package main

import (
	"net/http"
	"os/exec"
)

func RunCmd(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	// GOAST-CMD-001: tainted arg in exec.Command()
	out, _ := exec.Command("bash", "-c", cmd).Output()
	_ = out
	_ = w
}
