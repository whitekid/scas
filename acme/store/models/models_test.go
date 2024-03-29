package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	acmeclient "scas/client/acme"
	"scas/client/common"
	"scas/pkg/helper"
	"scas/pkg/helper/gormx"
	"scas/pkg/testutils"
)

func newFixture(t *testing.T, dbURL string) *fixture {
	db := testutils.Must1(gormx.Open(dbURL, &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix: "acme_",
		},
	}))
	testutils.Must(Migrate(db))

	proj := &Project{
		Name:       "test project",
		CommonName: "charlie.127.0.0.1.sslip.io",
	}
	require.NoError(t, db.Create(proj).Error)

	acct := &Account{
		Contacts:  []string{"mailto:hello@example.com"},
		Status:    acmeclient.AccountStatusValid.String(),
		Key:       goxp.RandomString(10),
		ProjectID: proj.ID,
	}
	require.NoError(t, db.Create(acct).Error)

	order := &Order{
		AccountID:   acct.ID,
		Status:      acmeclient.OrderStatusValid.String(),
		NotBefore:   &common.TimestampNow().Truncate(time.Minute).Time,
		NotAfter:    &common.TimestampNow().Truncate(time.Minute).Time,
		Identifiers: Identifier{Idents: []Ident{{Type: "dns", Value: "server1.charlie.127.0.0.1.sslip.io"}}},
		ProjectID:   proj.ID,
	}
	require.NoError(t, db.Create(order).Error)

	authz := &Authz{
		AccountID:  acct.ID,
		OrderID:    order.ID,
		Identifier: Identifier{Idents: []Ident{{Type: "dns", Value: "server1.charlie.127.0.0.1.sslip.io"}}},
		Status:     acmeclient.AuthzStatusValid.String(),
		Expires:    helper.NowP(),
		ProjectID:  proj.ID,
	}
	require.NoError(t, db.Create(authz).Error)

	return &fixture{
		DB:    db,
		proj:  proj,
		acct:  acct,
		order: order,
		authz: authz,
	}
}

type fixture struct {
	*gorm.DB

	proj  *Project
	acct  *Account
	order *Order
	authz *Authz
}

func TestProject(t *testing.T) {
	testutils.ForEachSQLDriver(t, func(t *testing.T, dbURL string, reset func()) {
		fixture := newFixture(t, dbURL)

		proj := &Project{
			Name:       "test",
			CommonName: "charlie.127.0.0.1.sslip.io",
		}
		require.NoError(t, fixture.Create(proj).Error)

		var got Project
		require.NoError(t, fixture.First(&got, "id = ?", proj.ID).Error)
	})
}

func TestTerm(t *testing.T) {
	testutils.ForEachSQLDriver(t, func(t *testing.T, dbURL string, reset func()) {
		fixture := newFixture(t, dbURL)

		term := &Term{ProjectID: fixture.proj.ID, Content: "term of service"}
		require.NoError(t, fixture.Create(term).Error)

		// FIXME Name, CommonName이 required여서 임시로 넣어줬음. 맘에 안드네.
		tx := fixture.Model(DummyProject).Where("id = ?", fixture.proj.ID).Update("term_id", term.ID)
		require.NoError(t, tx.Error)
		require.Equal(t, int64(1), tx.RowsAffected)
	})
}

func TestAccount(t *testing.T) {
	testutils.ForEachSQLDriver(t, func(t *testing.T, dbURL string, reset func()) {
		fixture := newFixture(t, dbURL)

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
					Contacts:  tt.args.contacts,
					Status:    acmeclient.AccountStatusValid.String(),
					Key:       goxp.RandomString(10),
					ProjectID: fixture.proj.ID,
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
	})
}

func TestAuthz(t *testing.T) {
	testutils.ForEachSQLDriver(t, func(t *testing.T, dbURL string, reset func()) {
		fixture := newFixture(t, dbURL)

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
					ProjectID:  fixture.proj.ID,
				}
				err := fixture.Create(authz).Error
				require.Truef(t, (err != nil) == tt.wantErr, `Authz() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
				if tt.wantErr {
					return
				}

				chal := &Challenge{
					AuthzID:   authz.ID,
					Type:      acmeclient.ChallengeTypeHttp01.String(),
					Status:    acmeclient.ChallengeStatusPending.String(),
					ProjectID: fixture.proj.ID,
				}
				require.NoError(t, fixture.Create(chal).Error)

				got := &Authz{}
				require.NoError(t, fixture.Preload("Challenges").First(got, "id = ?", authz.ID).Error)
				require.Equal(t, authz.ID, got.ID)
				require.NotEmpty(t, got.Challenges)
			})
		}
	})
}

func TestCertificate(t *testing.T) {
	testutils.ForEachSQLDriver(t, func(t *testing.T, dbURL string, reset func()) {
		fixture := newFixture(t, dbURL)

		cert := &Certificate{
			Chain:     goxp.RandomByte(20),
			ProjectID: fixture.proj.ID,
			OrderID:   fixture.order.ID,
		}
		require.NoError(t, fixture.Create(cert).Error)

		var got Certificate
		require.NoError(t, fixture.First(&got, "id = ?", cert.ID).Error)
	})
}
