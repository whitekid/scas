package common

import (
	"encoding/json"
	"time"

	"github.com/whitekid/goxp/fx"
)

// Timestamp RFC3339 timestamp
type Timestamp struct {
	time.Time
}

func NewTimestamp(t time.Time) *Timestamp { return &Timestamp{t} }
func NewTimestampP(t *time.Time) *Timestamp {
	return fx.TernaryCF(t == nil, func() *Timestamp { return nil }, func() *Timestamp { return &Timestamp{*t} })
}
func TimestampNow() *Timestamp { return NewTimestamp(time.Now().UTC()) }
func ParseTimestamp(s string) (*Timestamp, error) {
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, err
	}

	return NewTimestamp(tm), nil
}

func (t *Timestamp) String() string               { return t.Format(time.RFC3339) }
func (t *Timestamp) MarshalJSON() ([]byte, error) { return json.Marshal(t.String()) }
func (t *Timestamp) UnmarshalJSON(data []byte) error {
	var s string

	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}

	t.Time = tm
	return nil
}

func (t *Timestamp) MarshalYAML() (interface{}, error) { return t.Time, nil }
func (t *Timestamp) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tm time.Time
	if err := unmarshal(&tm); err != nil {
		return err
	}
	t.Time = tm
	return nil
}

func (t *Timestamp) AddDate(years, month, days int) *Timestamp {
	return NewTimestamp(t.Time.AddDate(years, month, days))
}

func (t *Timestamp) Add(d time.Duration) *Timestamp { return NewTimestamp(t.Time.Add(d)) }

func (t *Timestamp) Truncate(d time.Duration) *Timestamp {
	if t == nil {
		return nil
	}

	return NewTimestamp(t.Time.Truncate(d))
}
