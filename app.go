package scas

import (
	"context"

	echoSwagger "github.com/swaggo/echo-swagger"

	"scas/api/endpoints"
	_ "scas/api/v1alpha1"
	_ "scas/docs"
	"scas/pkg/helper"
)

func Run(ctx context.Context) error {
	e := newApp()
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	return helper.StartEcho(ctx, e, "127.0.0.1:8000")
}

func newApp() *helper.Echo {
	e := helper.NewEcho()
	endpoints.Route(e, endpoints.Endpoints()...)
	return e
}
