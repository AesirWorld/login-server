// This packages provides you with helper functions to authenticate and manage accounts
// It works directly with the backend database (MySQL)
package account

import "database/sql"
import _ "github.com/ziutek/mymysql/godrv" // Go driver for database/sql package
import "log"

var db, _ = sql.Open("mymysql", "tcp:127.0.0.1:3306*ragnarok/ragnarok/ragnarok")

func Connect() {
	err := db.Ping()

	if err != nil {
		log.Fatal(err)
	}
}

// Authenticate an user account, normally a player account
func Auth(username string, password string) (account_id int) {
	var query = "SELECT account_id FROM login WHERE sex != 'S' AND userid = ? AND user_pass = ? LIMIT 1"
	log.Println(username, password)
	rows, err := db.Query(query, username, password)

	if err != nil {
		log.Fatal(err)
	}

	for rows.Next() {
		if err := rows.Scan(&account_id); err != nil {
			log.Fatal(err)
		}

		break
	}

	return
}

// Authenticate an server, type S on the database
// This functions is generally used to authenticate a char-server or map-server
func AuthServer(username string, password string) (account_id int) {
	var query = "SELECT account_id FROM login WHERE sex = 'S' AND account_id < 2000000 AND userid = ? AND user_pass = ? LIMIT 1"

	rows, err := db.Query(query, username, password)

	if err != nil {
		log.Fatal(err)
	}

	for rows.Next() {
		if err := rows.Scan(&account_id); err != nil {
			log.Fatal(err)
		}

		break
	}

	return
}
