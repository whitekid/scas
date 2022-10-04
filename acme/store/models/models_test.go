package models

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	acmeclient "scas/client/acme"
	"scas/pkg/helper"
	"scas/pkg/helper/gormx"
	"scas/pkg/testutils"
)

func newFixture(t *testing.T) *fixture {
	dbname := testutils.DBName(t)
	os.RemoveAll(dbname + ".db")
	dburl := "sqlite://" + dbname + ".db"

	db := testutils.Must1(gormx.Open(dburl, &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix: "acme_",
		},
	}))
	testutils.Must(Migrate(db))

	acct := &Account{
		Contacts: []string{"mailto:hello@example.com"},
		Status:   acmeclient.AccountStatusValid.String(),
		Key:      goxp.RandomString(10),
	}
	require.NoError(t, db.Create(acct).Error)

	order := &Order{
		AccountID:   acct.ID,
		Status:      acmeclient.OrderStatusValid.String(),
		NotBefore:   helper.NowP(),
		NotAfter:    helper.NowP(),
		Identifiers: Identifier{Idents: []Ident{{Type: "dns", Value: "server1.charlie.127.0.0.1.sslip.io"}}},
	}
	require.NoError(t, db.Create(order).Error)

	authz := &Authz{
		AccountID:  acct.ID,
		OrderID:    order.ID,
		Identifier: Identifier{Idents: []Ident{{Type: "dns", Value: "server1.charlie.127.0.0.1.sslip.io"}}},
		Status:     acmeclient.AuthzStatusValid.String(),
		Expires:    helper.NowP(),
	}
	require.NoError(t, db.Create(authz).Error)

	return &fixture{
		DB:    db,
		acct:  acct,
		order: order,
		authz: authz,
	}
}

type fixture struct {
	*gorm.DB

	acct  *Account
	order *Order
	authz *Authz
}

func TestProject(t *testing.T) {
	fixture := newFixture(t)

	proj := &Project{
		Name: "test",
	}
	require.NoError(t, fixture.Create(proj).Error)

	var got Project
	require.NoError(t, fixture.First(&got).Error)
}

func TestAccount(t *testing.T) {
	fixture := newFixture(t)

	type args struct {
		contacts []string
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`empty contact`, args{}, true},
		{`valid`, args{[]string{"mailto:user1@example.com", "mailto:user2@example.com"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acct := &Account{
				Contacts: tt.args.contacts,
				Status:   acmeclient.AccountStatusValid.String(),
				Key:      goxp.RandomString(10),
			}
			err := fixture.Create(acct).Error
			require.Truef(t, (err != nil) == tt.wantErr, `Account() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
			if tt.wantErr {
				return
			}

			var got Account
			require.NoError(t, fixture.First(&got, "id = ?", acct.ID).Error)
			require.Equal(t, acct.ID, got.ID)
			require.Equal(t, acct.Contacts, got.Contacts)
		})
	}
}

func TestAuthz(t *testing.T) {
	fixture := newFixture(t)

	type args struct {
		idents Identifier
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`empty identifier type`, args{}, true},
		{`invalid identifier type`, args{NewIdentifier([]Ident{{Type: "", Value: "hello.example.com"}})}, true},
		{`valid`, args{NewIdentifier([]Ident{{Type: "dns", Value: "hello.example.com"}})}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authz := &Authz{
				AccountID:  fixture.acct.ID,
				OrderID:    fixture.order.ID,
				Identifier: tt.args.idents,
				Status:     acmeclient.AuthzStatusValid.String(),
				Expires:    helper.NowP(),
			}
			err := fixture.Create(authz).Error
			require.Truef(t, (err != nil) == tt.wantErr, `Authz() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
			if tt.wantErr {
				return
			}

			chal := &Challenge{
				AuthzID: authz.ID,
				Type:    acmeclient.ChallengeTypeHttp01.String(),
				Status:  acmeclient.ChallengeStatusPending.String(),
			}
			require.NoError(t, fixture.Create(chal).Error)

			got := &Authz{}
			require.NoError(t, fixture.Preload("Challenges").First(got, "id = ?", authz.ID).Error)
			require.Equal(t, authz.ID, got.ID)
			require.NotEmpty(t, got.Challenges)
		})
	}
}