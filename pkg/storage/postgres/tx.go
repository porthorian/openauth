package postgres

import (
	"context"
	"errors"

	"github.com/porthorian/openauth/pkg/storage"
)

var errNilTxCallback = errors.New("postgres adapter: transaction callback is nil")

func (a *Adapter) WithAuthMaterialTx(ctx context.Context, fn func(material storage.AuthMaterial) error) error {
	if fn == nil {
		return errNilTxCallback
	}

	if err := a.requirePreparedStatements(); err != nil {
		return err
	}

	db, err := a.requireDB()
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	txAdapter := &Adapter{
		db:    a.db,
		tx:    tx,
		stmts: a.stmts,
	}

	if err := fn(storage.AuthMaterial{
		Auth:        txAdapter,
		SubjectAuth: txAdapter,
		AuthLog:     txAdapter,
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true

	return nil
}
