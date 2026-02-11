package postgres

type Adapter struct{}

func NewAdapter() *Adapter {
	return &Adapter{}
}
