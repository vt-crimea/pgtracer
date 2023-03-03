// database
package database

import (
	//	"database/sql"

	_ "encoding/json"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

var DB *sqlx.DB

func Connect(connString string) (err error) {
	DB, err = sqlx.Connect("postgres", connString)
	return
}

func Test() (err error) {
	if DB == nil {
		return
	}
	_, err = DB.Exec(`select 'pgparser test'`)
	return
}

func CreateTables() (err error) {
	if DB == nil {
		return
	}
	_, err = DB.Exec(`create schema if not exists pgparser;`)
	if err != nil {
		return
	}

	_, err = DB.Exec(`create table if not exists pgparser.queries(id bigint generated always as identity, 
						ip varchar(14), port varchar(5), 
						querytext varchar, queryresult varchar, 
						timeStart timestamp, timefinish timestamp, errortext varchar)`)
	if err != nil {
		return
	}
	_, err = DB.Exec(`create table if not exists pgparser.params(id bigint generated always as identity, 
							queryid bigint, value varchar)`)
	return

}
