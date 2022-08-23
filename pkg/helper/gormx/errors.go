package gormx

import (
	"errors"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgconn"
	"github.com/mattn/go-sqlite3"
	"github.com/whitekid/goxp/log"
)

type sqlError struct {
	m string
}

func (e *sqlError) Error() string { return e.m }

func newSQLError(m string) error { return &sqlError{m: m} }

var (
	ErrForeignKeyConstraintFailed = newSQLError("FOREIGN KEY constraint failed")
	ErrUniqueConstraintFailed     = newSQLError("UNIQUE constraint failed")
)

func IsSQLError(err error) bool {
	var e *sqlError
	return errors.As(err, &e)
}

var (
	sqliteExtCodeToErr = map[sqlite3.ErrNoExtended]error{}
	mysqlErrCodeToErr  = map[uint16]error{}
	pgErrCodeToErr     = map[string]error{} // https://www.postgresql.org/docs/11/errcodes-appendix.html
)

func init() {
	sqlErrors := []struct {
		err          error
		sqliteErr    sqlite3.ErrNo
		sqliteExtErr sqlite3.ErrNoExtended
		mysqlCode    uint16
		pgCode       string
	}{
		{ErrUniqueConstraintFailed, sqlite3.ErrConstraint, 2067, 1062, "23505"},
		{ErrForeignKeyConstraintFailed, sqlite3.ErrConstraint, 787, 1452, "23503"},
	}
	for _, se := range sqlErrors {
		sqliteExtCodeToErr[se.sqliteExtErr] = se.err
		mysqlErrCodeToErr[se.mysqlCode] = se.err
		pgErrCodeToErr[se.pgCode] = se.err
	}
}

// ConvertSQLError convert grom underlaying sql driver errors
func ConvertSQLError(err error) error {
	if err == nil {
		return nil
	}

	if se, ok := err.(sqlite3.Error); ok {
		switch se.Code {
		case sqlite3.ErrConstraint:
			if ee, ok := sqliteExtCodeToErr[se.ExtendedCode]; ok {
				return ee
			}

			log.Debugf("\tUnhandled sqlite error: code=%d, extcode=%d", se.Code, se.ExtendedCode)
		}
		return err
	} else if me, ok := err.(*mysql.MySQLError); ok {
		if ee, ok := mysqlErrCodeToErr[me.Number]; ok {
			return ee
		}

		log.Debugf("\tUnhandled mysql error: code=%d, extcode=%s", me.Number, me.Message)
	} else if pe, ok := err.(*pgconn.PgError); ok {
		if ee, ok := pgErrCodeToErr[pe.Code]; ok {
			return ee
		}

		log.Debugf("\tUnhandled postgresql error: code=%s, detail=%s", pe.Code, pe.Detail)
	}

	return err
}
