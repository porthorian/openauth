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
	tx *sql.Tx

	stmts *preparedStatements
}

type preparedStatements struct {
	putAuth    *sql.Stmt
	getAuth    *sql.Stmt
	deleteAuth *sql.Stmt

	deleteAuthMetadata *sql.Stmt
	putAuthMetadata    *sql.Stmt
	getAuthMetadata    *sql.Stmt

	putSubjectAuth           *sql.Stmt
	listSubjectAuthBySubject *sql.Stmt
	listSubjectAuthByAuthID  *sql.Stmt
	deleteSubjectAuthByID    *sql.Stmt

	putAuthLog           *sql.Stmt
	listAuthLogByAuthID  *sql.Stmt
	listAuthLogBySubject *sql.Stmt

	deleteSubjectRoles               *sql.Stmt
	putSubjectRole                   *sql.Stmt
	listSubjectRoles                 *sql.Stmt
	deleteSubjectPermissionOverrides *sql.Stmt
	putSubjectPermissionOverride     *sql.Stmt
	listSubjectPermissionOverrides   *sql.Stmt

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
		label: "put subject auth",
		query: putSubjectAuthQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.putSubjectAuth = stmt
		},
	},
	{
		label: "list subject auth by subject",
		query: listSubjectAuthBySubjectQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.listSubjectAuthBySubject = stmt
		},
	},
	{
		label: "list subject auth by auth_id",
		query: listSubjectAuthByAuthIDQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.listSubjectAuthByAuthID = stmt
		},
	},
	{
		label: "delete subject auth by id",
		query: deleteSubjectAuthQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.deleteSubjectAuthByID = stmt
		},
	},
	{
		label: "put auth log",
		query: putAuthLogQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.putAuthLog = stmt
		},
	},
	{
		label: "list auth log by auth_id",
		query: listAuthLogByAuthIDQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.listAuthLogByAuthID = stmt
		},
	},
	{
		label: "list auth log by subject",
		query: listAuthLogBySubjectQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.listAuthLogBySubject = stmt
		},
	},
	{
		label: "delete subject roles",
		query: deleteSubjectRolesQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.deleteSubjectRoles = stmt
		},
	},
	{
		label: "put subject role",
		query: putSubjectRoleQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.putSubjectRole = stmt
		},
	},
	{
		label: "list subject roles",
		query: listSubjectRolesQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.listSubjectRoles = stmt
		},
	},
	{
		label: "delete subject permission overrides",
		query: deleteSubjectPermissionOverridesQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.deleteSubjectPermissionOverrides = stmt
		},
	},
	{
		label: "put subject permission override",
		query: putSubjectPermissionOverrideQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.putSubjectPermissionOverride = stmt
		},
	},
	{
		label: "list subject permission overrides",
		query: listSubjectPermissionOverridesQuery,
		assign: func(ps *preparedStatements, stmt *sql.Stmt) {
			ps.listSubjectPermissionOverrides = stmt
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
var _ storage.AuthMaterialTransactor = (*Adapter)(nil)

func NewAdapter(db *sql.DB) (*Adapter, error) {
	adapter := &Adapter{
		db: db,
		stmts: &preparedStatements{
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
	if a.tx != nil {
		return nil
	}
	if a.stmts == nil {
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
		a.stmts.putSubjectAuth,
		a.stmts.listSubjectAuthBySubject,
		a.stmts.listSubjectAuthByAuthID,
		a.stmts.deleteSubjectAuthByID,
		a.stmts.putAuthLog,
		a.stmts.listAuthLogByAuthID,
		a.stmts.listAuthLogBySubject,
		a.stmts.deleteSubjectRoles,
		a.stmts.putSubjectRole,
		a.stmts.listSubjectRoles,
		a.stmts.deleteSubjectPermissionOverrides,
		a.stmts.putSubjectPermissionOverride,
		a.stmts.listSubjectPermissionOverrides,
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
		spec.assign(a.stmts, stmt)
	}
	return nil
}

func (a *Adapter) requirePreparedStatements() error {
	if _, err := a.requireDB(); err != nil {
		return err
	}
	if a.stmts == nil {
		return ErrAdapterNotInitialized
	}

	if a.stmts.putAuth == nil || a.stmts.getAuth == nil || a.stmts.deleteAuth == nil {
		return ErrAdapterNotInitialized
	}
	if a.stmts.deleteAuthMetadata == nil || a.stmts.putAuthMetadata == nil || a.stmts.getAuthMetadata == nil {
		return ErrAdapterNotInitialized
	}
	if a.stmts.putSubjectAuth == nil || a.stmts.listSubjectAuthBySubject == nil || a.stmts.listSubjectAuthByAuthID == nil || a.stmts.deleteSubjectAuthByID == nil {
		return ErrAdapterNotInitialized
	}
	if a.stmts.putAuthLog == nil || a.stmts.listAuthLogByAuthID == nil || a.stmts.listAuthLogBySubject == nil {
		return ErrAdapterNotInitialized
	}
	if a.stmts.deleteSubjectRoles == nil || a.stmts.putSubjectRole == nil || a.stmts.listSubjectRoles == nil {
		return ErrAdapterNotInitialized
	}
	if a.stmts.deleteSubjectPermissionOverrides == nil || a.stmts.putSubjectPermissionOverride == nil || a.stmts.listSubjectPermissionOverrides == nil {
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
