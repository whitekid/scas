package testutils

import (
	"net/http"

	"scas/api/endpoints"
	"scas/pkg/helper"
)

func NewEndpointHandler(endpoint endpoints.Endpoint) http.Handler {
	handler := helper.NewEcho()
	endpoint.Route(handler.Group(""))

	return handler
}
