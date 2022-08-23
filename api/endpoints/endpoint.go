package endpoints

import (
	"github.com/labstack/echo/v4"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	"scas/pkg/helper"
)

// Endpoint (path, handler) pair
type Endpoint interface {
	PathAndName() (string, string)
	Route(g *echo.Group)
}

var endpoints []Endpoint

func Register(endpoint Endpoint) {
	if endpoint != nil {
		endpoints = append(endpoints, endpoint)
	}
}

func Endpoints() []Endpoint { return endpoints }

// Route route endpoint handlers
//
// TODO move to helper.Echo
func Route(e *helper.Echo, endpoints ...Endpoint) {
	fx.ForEach(endpoints, func(_ int, endpoint Endpoint) {
		path, name := endpoint.PathAndName()
		log.Debugf("%s -> %s", path, name)
		endpoint.Route(e.Group(path))
	})
}
