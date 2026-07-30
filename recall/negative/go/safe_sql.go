package main

import (
	"database/sql"
	"net/http"
)

func SafeGetUser(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	// Safe: parameterized query — first arg is literal SQL, id is a bind param
	rows, _ := db.Query("SELECT * FROM users WHERE id = ?", id)
	_ = rows
	_ = w
}
