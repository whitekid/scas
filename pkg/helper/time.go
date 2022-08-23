package helper

import (
	"time"
)

func NowP() *time.Time {
	t := time.Now().UTC()
	return &t
}

func AfterNow(years int, months int, days int) time.Time {
	return time.Now().UTC().Truncate(time.Hour*24).AddDate(years, months, days)
}

func AfterNowP(years, months, days int) *time.Time {
	t := AfterNow(years, months, days)
	return &t
}
