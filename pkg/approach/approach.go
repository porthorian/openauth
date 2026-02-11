package approach

import (
	"context"
	"errors"
	"time"
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
	ErrNilHandler    = errors.New("approach: handler is nil")
	ErrEmptyName     = errors.New("approach: handler name is empty")
	ErrDuplicateName = errors.New("approach: handler already exists")
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

	name := handler.Name()
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
	handler, ok := r.handlers[name]
	return handler, ok
}
