package acme

import (
	"context"

	"scas/api/endpoints"
	"scas/pkg/helper"
)

func Run(ctx context.Context) error {
	e := helper.NewEcho()
	endpoints.Route(e, New("127.0.0.1"))
	return helper.StartEcho(ctx, e, "127.0.0.1:8000")
}
