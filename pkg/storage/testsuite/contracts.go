package testsuite

import "context"

type PersistenceSuite interface {
	Run(ctx context.Context) error
}
