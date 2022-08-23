package store

import (
	"testing"
)

func TestStore(t *testing.T) {
	type args struct {
		store Interface
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		// {`valid`, args{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testScenario(t)
		})
	}
}

func testScenario(t *testing.T) {

}
