package main

import (
	"database/sql"
	"os/exec"
)

func queryUser(db *sql.DB, userId string) {
	query := "SELECT * FROM users WHERE id = " + userId
	db.Query(query)
}

func pingHost(host string) {
	cmdStr := "ping -c 3 " + host
	exec.Command("sh", "-c", cmdStr)
}
