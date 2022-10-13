package pkg

import (
	"testing"
)

func TestComparable(t *testing.T) {
	type args struct {
		k any
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`valid`, args{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// got, err := doSomething()
			// require.Truef(t, (err != nil) == tt.wantErr, `doSomething() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
			// if tt.wantErr {
			// 	return
			// }
			// _ = got
		})
	}
}
