package x509types

// CRL relatedd types

import "encoding/json"

// RevokeReason Revoke reason code. see RFC5280 5.3.1
type RevokeReason int

const (
	RevokeUnspecified          RevokeReason = iota
	RevokeKeyCompromise        RevokeReason = 1
	RevokeCACompromise         RevokeReason = 2
	RevokeAffiliationChanged   RevokeReason = 3
	RevokeSuperseded           RevokeReason = 4
	RevokeCessationOfOperation RevokeReason = 5
	RevokeCertificateHold      RevokeReason = 6
	RevokeRemoveFromCRL        RevokeReason = 8
	RevokePrivilegeWithdrawn   RevokeReason = 9
	RevokeAACompromise         RevokeReason = 10
)

var (
	revokeReasonToStr = map[RevokeReason]string{
		RevokeUnspecified:          "unspecified",
		RevokeKeyCompromise:        "keyCompromise",
		RevokeCACompromise:         "CACompromise",
		RevokeAffiliationChanged:   "affiliationChanged",
		RevokeSuperseded:           "superseded",
		RevokeCessationOfOperation: "cessationOfOperation",
		RevokeCertificateHold:      "certificateHold",
		RevokeRemoveFromCRL:        "removeFromCRL",
		RevokePrivilegeWithdrawn:   "privilegeWithdrawn",
		RevokeAACompromise:         "AACompromise",
	}
	revokeStrToReason = map[string]RevokeReason{}
)

func init() {
	for reason, str := range revokeReasonToStr {
		revokeStrToReason[str] = reason
	}
}

func (r RevokeReason) String() string         { return revokeReasonToStr[r] }
func StrToRevokeReason(s string) RevokeReason { return revokeStrToReason[s] }

func (s RevokeReason) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }
func (s *RevokeReason) UnmarshalJSON(data []byte) error {
	var str string

	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	*s = StrToRevokeReason(str)

	return nil
}
