package main

import (
	"database/sql"
	"os/exec"
)

func queryUser(db *sql.DB, userId string) {
	db.Query("SELECT * FROM users WHERE id = ?", userId)
}

func pingHost(host string) {
	exec.Command("ping", "-c", "3", host)
}
