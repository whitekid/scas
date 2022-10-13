package testutils

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp/fx"
)

func DBName(name string) string {
	return strings.ToLower(strings.NewReplacer(
		"/", "_",
		":", "_",
		"#", "_",
	).Replace(name))
}

func ForEachSQLDriver(t *testing.T, testfn func(t *testing.T, dbURL string, reset func())) {
	fx.ForEach([]string{"sqlite", "mysql", "pgsql"}, func(_ int, driver string) {
		if os.Getenv("SCAS_SKIP_SQL_"+strings.ToUpper(driver)) == "true" {
			t.Skip("skip driver " + driver)
			return
		}

		ForOneSQLDriver(t, driver, testfn)
	})
}

func ForOneSQLDriver(t *testing.T, driver string, testfn func(t *testing.T, dbURL string, reset func())) {
	t.Run(driver, func(t *testing.T) {
		dbname := DBName(t.Name())
		dburl := ""
		var db *sql.DB
		var err error
		var reset = func() {}
		switch driver {
		case "sqlite":
			reset = func() { os.Remove(dbname + ".db") }
			dburl = fmt.Sprintf("sqlite://%s.db", dbname)

		case "mysql":
			db, err = sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/mysql")
			require.NoError(t, err)

			reset = func() {
				_, err := db.Exec("DROP DATABASE IF EXISTS" + dbname)
				require.NoError(t, err)

				_, err = db.Exec("CREATE DATABASE " + dbname)
				require.NoError(t, err)
			}

			dburl = fmt.Sprintf("mysql://root:@127.0.0.1:3306/%s?parseTime=true", dbname)

		case "pgsql":
			db, err := sql.Open("pgx", "dbname=postgres")
			require.NoError(t, err)

			reset = func() {
				_, err = db.Exec("DROP DATABASE IF EXISTS " + dbname)
				require.NoError(t, err)
				_, err = db.Exec("CREATE DATABASE " + dbname)
				require.NoError(t, err)
			}

			dburl = fmt.Sprintf("postgresql:///%s", dbname)

		default:
			require.Failf(t, "not supported scheme", driver)
		}

		reset()
		testfn(t, dburl, reset)
	})
}
