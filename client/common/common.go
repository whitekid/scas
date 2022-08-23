package common

import "encoding/json"

type Status int

const (
	StatusNone Status = iota
	StatusCreating
	StatusCreated
	StatusActive
	StatusSuspended
	StatusRevoked
)

var (
	statusToStr = map[Status]string{}
	strToStatus = map[string]Status{}
)

func init() {
	for status, str := range map[Status]string{
		StatusNone:      "",
		StatusCreating:  "creating",
		StatusCreated:   "created",
		StatusActive:    "active",
		StatusSuspended: "suspended",
		StatusRevoked:   "revoked",
	} {
		statusToStr[status] = str
		strToStatus[str] = status
	}
}

func (st Status) String() string               { return statusToStr[st] }
func (st Status) MarshalJSON() ([]byte, error) { return json.Marshal(st.String()) }
func (st *Status) UnmarshalJSON(data []byte) error {
	var s string

	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	*st = strToStatus[s]

	return nil
}

func StrToStatus(s string) Status { return strToStatus[s] }
