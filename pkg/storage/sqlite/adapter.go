package sqlite

type Adapter struct{}

func NewAdapter() *Adapter {
	return &Adapter{}
}
