package crypto

import "errors"

var (
	ErrInvalidHash   = errors.New("password: invalid hash")
	ErrInvalidConfig = errors.New("password: invalid config")
)

type Hasher interface {
	Hash(password string) (string, error)
	Verify(password string, encodedHash string) (bool, error)
}
