package main

import (
	"database/sql"
	"net/http"
)

func GetUser(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	// GOAST-SQL-001: tainted string concatenated into db.Query() first arg
	rows, _ := db.Query("SELECT * FROM users WHERE id = " + id)
	_ = rows
	_ = w
}
