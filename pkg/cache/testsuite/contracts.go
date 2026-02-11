package testsuite

import "context"

type CacheSuite interface {
	Run(ctx context.Context) error
}
