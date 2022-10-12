package testutils

import (
	"testing"
)

func TestDBName(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"many slash", args{name: "Test_sqlStoreImpl_listCertificate/pgsql/status"}, "test_sqlstoreimpl_listcertificate_pgsql_status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DBName(tt.args.name); got != tt.want {
				t.Errorf("DBName() = %v, want %v", got, tt.want)
			}
		})
	}
}
