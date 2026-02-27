package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/porthorian/openauth/pkg/storage"
)

type Adapter struct {
	db *sql.DB

	stmts preparedStatements
}

type preparedStatements struct {
	putAuth    *sql.Stmt
	getAuth    *sql.Stmt
	deleteAuth *sql.Stmt

	deleteAuthMetadata *sql.Stmt
	putAuthMetadata    *sql.Stmt
	getAuthMetadata    *sql.Stmt

	putAuthUser          *sql.Stmt
	listAuthUserByUserID *sql.Stmt
	listAuthUserByAuthID *sql.Stmt
	deleteAuthUserByID   *sql.Stmt

	putAuthEvent           *sql.Stmt
	listAuthEventByAuthID  *sql.Stmt
	listAuthEventBySubject *sql.Stmt

	getAuthsMu     sync.Mutex
	getAuthsBySize map[int]*sql.Stmt
}

type prepareStatementSpec struct {
	label  string
	query  string
	assign func(*preparedStatements, *sql.Stmt)
}

var fixedPrepareStatementSpecs = []prepareStatementSpec{
	{
		label: "put auth",
		query: putAuthQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.putAuth = stmt
		},
	},
	{
		label: "get auth",
		query: getAuthQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.getAuth = stmt
		},
	},
	{
		label: "delete auth",
		query: deleteAuthQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.deleteAuth = stmt
		},
	},
	{
		label: "delete auth metadata",
		query: deleteAuthMetadataQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.deleteAuthMetadata = stmt
		},
	},
	{
		label: "put auth metadata",
		query: putAuthMetadataQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.putAuthMetadata = stmt
		},
	},
	{
		label: "get auth metadata",
		query: getAuthMetadataQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.getAuthMetadata = stmt
		},
	},
	{
		label: "put auth user",
		query: putAuthUserQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.putAuthUser = stmt
		},
	},
	{
		label: "list auth user by user_id",
		query: listAuthUserByUserIDQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.listAuthUserByUserID = stmt
		},
	},
	{
		label: "list auth user by auth_id",
		query: listAuthUserByAuthIDQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.listAuthUserByAuthID = stmt
		},
	},
	{
		label: "delete auth user by id",
		query: deleteAuthUserQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.deleteAuthUserByID = stmt
		},
	},
	{
		label: "put auth event",
		query: putAuthEventQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.putAuthEvent = stmt
		},
	},
	{
		label: "list auth event by auth_id",
		query: listAuthEventByAuthIDQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.listAuthEventByAuthID = stmt
		},
	},
	{
		label: "list auth event by subject",
		query: listAuthEventBySubjectQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.listAuthEventBySubject = stmt
		},
	},
}

var (
	ErrNilDB                 = errors.New("postgres adapter: db is nil")
	ErrAdapterNotInitialized = errors.New("postgres adapter: adapter not initialized")
	ErrNotImplemented        = errors.New("postgres adapter: method not implemented")
)

var _ storage.AuthStore = (*Adapter)(nil)
var _ storage.SubjectAuthStore = (*Adapter)(nil)
var _ storage.AuthLogStore = (*Adapter)(nil)
var _ storage.RoleStore = (*Adapter)(nil)
var _ storage.PermissionStore = (*Adapter)(nil)

func NewAdapter(db *sql.DB) (*Adapter, error) {
	adapter := &Adapter{
		db: db,
		stmts: preparedStatements{
			getAuthsBySize: map[int]*sql.Stmt{},
		},
	}

	if err := adapter.prepareStatements(); err != nil {
		_ = adapter.Close()
		return nil, err
	}

	return adapter, nil
}

func (a *Adapter) Close() error {
	if a == nil {
		return nil
	}

	var errs []error

	if err := closeStatements(
		a.stmts.putAuth,
		a.stmts.getAuth,
		a.stmts.deleteAuth,
		a.stmts.deleteAuthMetadata,
		a.stmts.putAuthMetadata,
		a.stmts.getAuthMetadata,
		a.stmts.putAuthUser,
		a.stmts.listAuthUserByUserID,
		a.stmts.listAuthUserByAuthID,
		a.stmts.deleteAuthUserByID,
		a.stmts.putAuthEvent,
		a.stmts.listAuthEventByAuthID,
		a.stmts.listAuthEventBySubject,
	); err != nil {
		errs = append(errs, err)
	}

	a.stmts.getAuthsMu.Lock()
	dynamicStmts := make([]*sql.Stmt, 0, len(a.stmts.getAuthsBySize))
	for _, stmt := range a.stmts.getAuthsBySize {
		dynamicStmts = append(dynamicStmts, stmt)
	}
	a.stmts.getAuthsBySize = map[int]*sql.Stmt{}
	a.stmts.getAuthsMu.Unlock()

	if err := closeStatements(dynamicStmts...); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (a *Adapter) prepareStatements() (err error) {
	db, err := a.requireDB()
	if err != nil {
		return err
	}

	prepared := make([]*sql.Stmt, 0, len(fixedPrepareStatementSpecs))
	defer func() {
		if err != nil {
			_ = closeStatements(prepared...)
		}
	}()

	for _, spec := range fixedPrepareStatementSpecs {
		stmt, prepErr := db.Prepare(spec.query)
		if prepErr != nil {
			err = fmt.Errorf("postgres adapter: prepare %s statement: %w", spec.label, prepErr)
			return err
		}
		prepared = append(prepared, stmt)
		spec.assign(&a.stmts, stmt)
	}
	return nil
}

func (a *Adapter) requirePreparedStatements() error {
	if _, err := a.requireDB(); err != nil {
		return err
	}

	if a.stmts.putAuth == nil || a.stmts.getAuth == nil || a.stmts.deleteAuth == nil {
		return ErrAdapterNotInitialized
	}
	if a.stmts.deleteAuthMetadata == nil || a.stmts.putAuthMetadata == nil || a.stmts.getAuthMetadata == nil {
		return ErrAdapterNotInitialized
	}
	if a.stmts.putAuthUser == nil || a.stmts.listAuthUserByUserID == nil || a.stmts.listAuthUserByAuthID == nil || a.stmts.deleteAuthUserByID == nil {
		return ErrAdapterNotInitialized
	}
	if a.stmts.putAuthEvent == nil || a.stmts.listAuthEventByAuthID == nil || a.stmts.listAuthEventBySubject == nil {
		return ErrAdapterNotInitialized
	}

	return nil
}

func (a *Adapter) requireDB() (*sql.DB, error) {
	if a == nil || a.db == nil {
		return nil, ErrNilDB
	}
	return a.db, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func closeStatements(stmts ...*sql.Stmt) error {
	var errs []error
	for _, stmt := range stmts {
		if stmt == nil {
			continue
		}
		if err := stmt.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
