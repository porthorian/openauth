package approach

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	NameDirectJWT           = "direct_jwt"
	NameOpaqueIntrospection = "opaque_introspection"
	NamePhantomToken        = "phantom_token"
)

type Result struct {
	Subject   string
	Tenant    string
	Claims    map[string]any
	ExpiresAt time.Time
}

type Handler interface {
	Name() string
	Validate(ctx context.Context, token string) (Result, error)
}

type Registry struct {
	handlers map[string]Handler
}

var (
	ErrNilHandler      = errors.New("approach: handler is nil")
	ErrNilRegistry     = errors.New("approach: registry is nil")
	ErrEmptyName       = errors.New("approach: handler name is empty")
	ErrDuplicateName   = errors.New("approach: handler already exists")
	ErrHandlerNotFound = errors.New("approach: handler not found")
)

func NewRegistry(handlers ...Handler) (*Registry, error) {
	r := &Registry{
		handlers: map[string]Handler{},
	}

	for _, handler := range handlers {
		if err := r.Register(handler); err != nil {
			return nil, err
		}
	}

	return r, nil
}

func (r *Registry) Register(handler Handler) error {
	if handler == nil {
		return ErrNilHandler
	}

	name := strings.TrimSpace(handler.Name())
	if name == "" {
		return ErrEmptyName
	}

	if _, exists := r.handlers[name]; exists {
		return ErrDuplicateName
	}

	r.handlers[name] = handler
	return nil
}

func (r *Registry) Handler(name string) (Handler, bool) {
	handler, ok := r.handlers[strings.TrimSpace(name)]
	return handler, ok
}

func (r *Registry) Validate(ctx context.Context, name string, token string) (Result, error) {
	if r == nil {
		return Result{}, ErrNilRegistry
	}

	approachName := strings.TrimSpace(name)
	if approachName == "" {
		return Result{}, ErrEmptyName
	}

	handler, ok := r.Handler(approachName)
	if !ok {
		return Result{}, fmt.Errorf("%w: %s", ErrHandlerNotFound, approachName)
	}

	return handler.Validate(ctx, token)
}
