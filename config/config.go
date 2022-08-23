package config

import "time"

func CRLNextUpdateDuration() time.Duration { return time.Hour * 24 * 7 }
func CRLNextUpdateTimeout() time.Duration  { return time.Minute * 30 }
