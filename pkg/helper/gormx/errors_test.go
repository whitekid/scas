package gormx

import (
	"os"
	"testing"

	"scas/pkg/testutils"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type Post struct {
	*gorm.Model
	Title    string     `gorm:"uniqueIndex;size:100;check:title <> ''"`
	Comments []*Comment `gorm:"foreignKey:PostID"`
}

type Comment struct {
	*gorm.Model
	PostID uint
}

func TestErrors(t *testing.T) {
	if _, ok := os.LookupEnv("GITHUB_ACTION"); !ok {
		os.Setenv("SCAS_SKIP_SQL_SQLITE", "false")
		os.Setenv("SCAS_SKIP_SQL_MYSQL", "false")
		os.Setenv("SCAS_SKIP_SQL_PGSQL", "false")
	}

	testutils.ForEachSQLDriver(t, func(t *testing.T, dbURL string, reset func()) {
		db, err := Open(dbURL)
		require.NoError(t, err)
		require.NoError(t, db.AutoMigrate(&Post{}, &Comment{}))

		type args struct {
			op func() error
		}
		tests := [...]struct {
			name    string
			args    args
			wantErr error
		}{
			{`check constraint`, args{func() error {
				return db.Create(&Post{}).Error
			}}, ErrCheckConstraintFailed},
			{`foreign key constraint`, args{func() error {
				return db.Create(&Comment{}).Error
			}}, ErrForeignKeyConstraintFailed},
			{`unique index`, args{func() error {
				require.NoError(t, db.Create(&Post{Title: "hello"}).Error)
				return db.Create(&Post{Title: "hello"}).Error
			}}, ErrUniqueConstraintFailed},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := ConvertSQLError(tt.args.op())
				require.ErrorIs(t, err, tt.wantErr, `unexpected error: error = %+v, wantErr = %v`, err, tt.wantErr)
			})
		}
	})
}
