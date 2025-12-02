package conf

import (
	"net/http"
	"slider/pkg/types"
	"strings"
)

// RouteHandler defines a handler function for a route
type RouteHandler func(w http.ResponseWriter, r *http.Request, handler *types.HttpHandler) error

// PrefixRoute represents a route that matches URL path prefixes
type PrefixRoute struct {
	Prefix  string
	Handler RouteHandler
}

// Router manages HTTP routes with support for exact and prefix matching
type Router struct {
	exactRoutes  map[string]RouteHandler
	prefixRoutes []PrefixRoute
	notFound     RouteHandler
}

// NewRouter creates a new router with default 404 handler
func NewRouter() *Router {
	return &Router{
		exactRoutes:  make(map[string]RouteHandler),
		prefixRoutes: make([]PrefixRoute, 0),
		notFound:     defaultNotFoundHandler,
	}
}

// HandleExact registers a handler for an exact path match
func (rt *Router) HandleExact(path string, handler RouteHandler) {
	rt.exactRoutes[path] = handler
}

// HandlePrefix registers a handler for paths matching a prefix
// Prefix routes are checked in registration order
func (rt *Router) HandlePrefix(prefix string, handler RouteHandler) {
	rt.prefixRoutes = append(rt.prefixRoutes, PrefixRoute{
		Prefix:  prefix,
		Handler: handler,
	})
}

// ServeHTTP routes the request to the appropriate handler
// Priority: exact matches first, then prefix matches in order, then 404
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request, handler *types.HttpHandler) error {
	// Check exact matches first (O(1) map lookup)
	if h, ok := rt.exactRoutes[r.URL.Path]; ok {
		return h(w, r, handler)
	}

	// Check prefix matches in registration order
	for _, route := range rt.prefixRoutes {
		if strings.HasPrefix(r.URL.Path, route.Prefix) {
			return route.Handler(w, r, handler)
		}
	}

	// No match found, use 404 handler
	return rt.notFound(w, r, handler)
}

// defaultNotFoundHandler returns a 404 response
func defaultNotFoundHandler(w http.ResponseWriter, r *http.Request, handler *types.HttpHandler) error {
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("Not found"))
	return nil
}
