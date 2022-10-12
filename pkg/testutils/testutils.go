package testutils

import (
	"fmt"
	"strings"
)

func Must(err error) {
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
}

func Must1[T any](v T, err error) T {
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
	return v
}

func DBName(name string) string {
	return strings.ToLower(strings.NewReplacer(
		"/", "_",
		":", "_",
		"#", "_",
	).Replace(name))
}
