package gormx

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/whitekid/goxp"
	"github.com/whitekid/goxp/log"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"scas/pkg/helper"
)

// Open open database
func Open(dburl string, opts ...gorm.Option) (*gorm.DB, error) {
	u, err := url.Parse(dburl)
	if err != nil {
		return nil, err
	}

	var dialector gorm.Dialector

	switch strings.ToLower(u.Scheme) {
	case "sqlite", "sqlite3":
		log.Debugf("opening sqlite...: %s", u.Hostname())
		dialector = sqlite.Open(u.Hostname())

	case "my", "mysql", "mariadb":
		log.Debugf("opening mysql...")
		dialector = newMySQLDialector(u)

	case "pg", "psql", "pgsql", "postgres", "postgresql":
		log.Debugf("opening postgresql...")
		dialector = newPgDialector(u)
	}

	if dialector == nil {
		panic(fmt.Sprintf("unsupported schme: %s", dburl))
	}

	db, err := gorm.Open(dialector, opts...)
	if err != nil {
		panic(err)
	}

	switch u.Scheme {
	case "sqlite", "sqlite3":
		if r := db.Exec("PRAGMA foreign_keys = ON"); r.Error != nil {
			panic(r.Error)
		}
	}

	db.Use(NewValidationPlugin())

	return db, nil
}

func newMySQLDialector(u *url.URL) gorm.Dialector {
	queries := u.Query()
	params := url.Values{}
	passwd, _ := u.User.Password()

	goxp.IfThen(queries.Get("charset") != "", func() { params.Set("charset", queries.Get("charset")) })
	goxp.IfThen(queries.Get("parseTime") != "", func() { params.Set("parseTime", queries.Get("parseTime")) })
	goxp.IfThen(queries.Get("loc") != "", func() { params.Set("loc", queries.Get("loc")) })

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)%s?%s", u.User.Username(), passwd, u.Hostname(), u.Port(), u.Path, params.Encode())

	config := mysql.Config{DSN: dsn}
	goxp.IfThen(queries.Get("DefaultStringSize") != "", func() { config.DefaultStringSize = helper.AtoiDef(queries.Get("DefaultStringSize"), uint(0)) })
	goxp.IfThen(queries.Get("DisableDatetimePrecision") != "", func() {
		config.DisableDatetimePrecision = helper.ParseBoolDef(queries.Get("DisableDatetimePrecision"), false)
	})
	goxp.IfThen(queries.Get("DisableDatetimePrecision") != "", func() {
		config.DisableDatetimePrecision = helper.ParseBoolDef(queries.Get("DisableDatetimePrecision"), false)
	})
	goxp.IfThen(queries.Get("DontSupportRenameIndex") != "", func() {
		config.DontSupportRenameIndex = helper.ParseBoolDef(queries.Get("DontSupportRenameIndex"), false)
	})
	goxp.IfThen(queries.Get("SkipInitializeWithVersion") != "", func() {
		config.SkipInitializeWithVersion = helper.ParseBoolDef(queries.Get("SkipInitializeWithVersion"), false)
	})

	return mysql.New(config)
}

func newPgDialector(u *url.URL) gorm.Dialector {
	queries := u.Query()
	passwd, _ := u.User.Password()
	params := []string{}

	goxp.IfThen(u.Hostname() != "", func() { params = append(params, fmt.Sprintf("host=%s", u.Hostname())) })
	goxp.IfThen(u.User.Username() != "", func() { params = append(params, fmt.Sprintf("user=%s", u.User.Username())) })
	goxp.IfThen(u.Path != "", func() { params = append(params, fmt.Sprintf("database=%s", strings.TrimLeft(u.Path, "/"))) })
	goxp.IfThen(passwd != "", func() { params = append(params, fmt.Sprintf("password=%s", passwd)) })
	goxp.IfThen(u.Port() != "", func() { params = append(params, fmt.Sprintf("port=%s", u.Port())) })
	goxp.IfThen(queries.Get("sslmode") != "", func() { params = append(params, fmt.Sprintf("sslmode=%s", queries.Get("sslmode"))) })
	goxp.IfThen(queries.Get("timezone") != "", func() { params = append(params, fmt.Sprintf("TimeZone=%s", queries.Get("timezone"))) })

	dsn := strings.Join(params, " ")

	config := postgres.Config{DSN: dsn}
	goxp.IfThen(queries.Get("PreferSimpleProtocol") != "", func() {
		config.PreferSimpleProtocol = helper.ParseBoolDef(queries.Get("PreferSimpleProtocol"), false)
	})
	goxp.IfThen(queries.Get("WithoutReturning") != "", func() {
		config.WithoutReturning = helper.ParseBoolDef(queries.Get("WithoutReturning"), false)
	})

	return postgres.New(config)
}

func Count(tx *gorm.DB) int64 {
	var c int64
	if t := tx.Count(&c); t.Error != nil {
		panic(t.Error)
	}
	return c
}
