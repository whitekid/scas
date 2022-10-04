package models

import "github.com/lithammer/shortuuid/v4"

func genID(id *string) error {
	*id = shortuuid.New()
	return nil
}
