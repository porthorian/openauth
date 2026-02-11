package grpctransport

import "context"

type TokenValidator interface {
	Validate(ctx context.Context, token string) (any, error)
}

type UnaryHandler func(ctx context.Context, req any) (any, error)

type UnaryServerInfo struct {
	FullMethod string
}

type UnaryServerInterceptor func(ctx context.Context, req any, info *UnaryServerInfo, handler UnaryHandler) (any, error)

type ServerStream interface {
	Context() context.Context
}

type StreamHandler func(srv any, stream ServerStream) error

type StreamServerInfo struct {
	FullMethod string
}

type StreamServerInterceptor func(srv any, stream ServerStream, info *StreamServerInfo, handler StreamHandler) error

func UnaryInterceptor(_ TokenValidator) UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *UnaryServerInfo, handler UnaryHandler) (any, error) {
		return handler(ctx, req)
	}
}

func StreamInterceptor(_ TokenValidator) StreamServerInterceptor {
	return func(srv any, stream ServerStream, info *StreamServerInfo, handler StreamHandler) error {
		return handler(srv, stream)
	}
}
