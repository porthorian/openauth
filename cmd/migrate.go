package cmd

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	migratedatabase "github.com/golang-migrate/migrate/v4/database"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/lib/pq"
	"github.com/spf13/cobra"
)

type migrateConfig struct {
	Driver          string
	DatabaseURL     string
	MigrationsTable string
	MigrationsPath  string
}

func init() {
	rootCmd.AddCommand(newMigrateCommand())
}

func newMigrateCommand() *cobra.Command {
	cfg := migrateConfig{
		Driver:          "postgres",
		MigrationsTable: "openauth.schema_migrations",
	}

	migrateCmd := &cobra.Command{
		Use:   "migrate",
		Short: "Run OpenAuth migration and seed routines",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	migrateCmd.PersistentFlags().StringVar(&cfg.Driver, "driver", cfg.Driver, "Source-of-truth backend driver. Supported: postgres.")
	migrateCmd.PersistentFlags().StringVar(&cfg.DatabaseURL, "database-url", "", "Database connection URL. Can also be set via OPENAUTH_MIGRATE_DATABASE_URL.")
	migrateCmd.PersistentFlags().StringVar(&cfg.MigrationsTable, "migrations-table", cfg.MigrationsTable, "Migrations version table name. Supports table or schema.table format. Can also be set via OPENAUTH_MIGRATE_MIGRATIONS_TABLE.")
	migrateCmd.PersistentFlags().StringVar(&cfg.MigrationsPath, "migrations-path", "", "Path or source URL for migration files. Defaults by driver under pkg/storage/<driver>/migrations.")

	migrateCmd.AddCommand(&cobra.Command{
		Use:   "up [steps]",
		Short: "Run schema migrations up",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			steps, hasSteps, err := parseMigrationStepsArg(args)
			if err != nil {
				return err
			}

			runner, sourceURL, err := newMigrationRunner(cfg)
			if err != nil {
				return err
			}
			defer func() {
				if closeErr := closeMigrationRunner(runner); closeErr != nil {
					cmd.PrintErrf("warning: failed to close migration runner cleanly: %v\n", closeErr)
				}
			}()

			if hasSteps {
				err = runner.Steps(steps)
			} else {
				err = runner.Up()
			}

			if err != nil {
				if isNoChangeBoundaryError(err) {
					cmd.Println("No schema changes to apply.")
					return nil
				}

				var shortLimit migrate.ErrShortLimit
				if hasSteps && errors.As(err, &shortLimit) {
					applied := steps - int(shortLimit.Short)
					if applied <= 0 {
						cmd.Println("No schema changes to apply.")
						return nil
					}

					cmd.Printf(
						"Applied %d migration step(s) from %s (requested %d step(s), reached migration boundary)\n",
						applied,
						sourceURL,
						steps,
					)
					return nil
				}

				return fmt.Errorf("apply migrations: %w", err)
			}

			if hasSteps {
				cmd.Printf("Applied %d migration step(s) from %s\n", steps, sourceURL)
				return nil
			}

			cmd.Printf("Applied all pending migrations from %s\n", sourceURL)
			return nil
		},
	})

	migrateCmd.AddCommand(&cobra.Command{
		Use:   "down <steps>",
		Short: "Rollback schema migrations down by step count",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			steps, _, err := parseMigrationStepsArg(args)
			if err != nil {
				return err
			}
			migrationsTable := resolveMigrationsTable(cfg.MigrationsTable)

			runner, sourceURL, err := newMigrationRunner(cfg)
			if err != nil {
				return err
			}
			defer func() {
				if closeErr := closeMigrationRunner(runner); closeErr != nil {
					cmd.PrintErrf("warning: failed to close migration runner cleanly: %v\n", closeErr)
				}
			}()

			if err := runner.Steps(-steps); err != nil {
				if isNoChangeBoundaryError(err) {
					cmd.Println("No schema changes to rollback.")
					return nil
				}
				if isDroppedMigrationsTableError(err, migrationsTable) {
					cmd.Printf("Rolled back %d migration step(s) from %s\n", steps, sourceURL)
					cmd.Println("Migration tracking table was removed by rollback and will be recreated on the next run.")
					return nil
				}

				var shortLimit migrate.ErrShortLimit
				if errors.As(err, &shortLimit) {
					rolledBack := steps - int(shortLimit.Short)
					if rolledBack <= 0 {
						cmd.Println("No schema changes to rollback.")
						return nil
					}

					cmd.Printf(
						"Rolled back %d migration step(s) from %s (requested %d step(s), reached migration boundary)\n",
						rolledBack,
						sourceURL,
						steps,
					)
					return nil
				}

				return fmt.Errorf("rollback migrations: %w", err)
			}

			cmd.Printf("Rolled back %d migration step(s) from %s\n", steps, sourceURL)
			return nil
		},
	})

	migrateCmd.AddCommand(&cobra.Command{
		Use:   "force <version>",
		Short: "Force-set migration version (-1 for nil version)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			version, err := parseForceVersionArg(args[0])
			if err != nil {
				return err
			}

			runner, _, err := newMigrationRunner(cfg)
			if err != nil {
				return err
			}
			defer func() {
				if closeErr := closeMigrationRunner(runner); closeErr != nil {
					cmd.PrintErrf("warning: failed to close migration runner cleanly: %v\n", closeErr)
				}
			}()

			if err := runner.Force(version); err != nil {
				return fmt.Errorf("force migration version: %w", err)
			}

			if version == -1 {
				cmd.Println("Forced migration version to -1 (no version).")
				return nil
			}

			cmd.Printf("Forced migration version to %d.\n", version)
			return nil
		},
	})

	return migrateCmd
}

func lookupEnv(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func resolveDatabaseURL(databaseURLFlag string) (string, error) {
	databaseURL := strings.TrimSpace(databaseURLFlag)
	if databaseURL == "" {
		databaseURL = lookupEnv("OPENAUTH_MIGRATE_DATABASE_URL")
	}
	if databaseURL == "" {
		databaseURL = lookupEnv("OPENAUTH_DATABASE_URL")
	}
	if databaseURL == "" {
		return "", errors.New("missing database URL: set --database-url or OPENAUTH_MIGRATE_DATABASE_URL")
	}
	return databaseURL, nil
}

func parseMigrationStepsArg(args []string) (int, bool, error) {
	if len(args) == 0 {
		return 0, false, nil
	}

	steps, err := strconv.Atoi(strings.TrimSpace(args[0]))
	if err != nil || steps <= 0 {
		return 0, false, fmt.Errorf("invalid migration steps %q: expected a positive integer", args[0])
	}

	return steps, true, nil
}

func parseForceVersionArg(arg string) (int, error) {
	version, err := strconv.Atoi(strings.TrimSpace(arg))
	if err != nil || version < -1 {
		return 0, fmt.Errorf("invalid force version %q: expected an integer >= -1", arg)
	}
	return version, nil
}

func newMigrationRunner(cfg migrateConfig) (*migrate.Migrate, string, error) {
	databaseURL, err := resolveDatabaseURL(cfg.DatabaseURL)
	if err != nil {
		return nil, "", err
	}
	migrationsTable := resolveMigrationsTable(cfg.MigrationsTable)
	if err := ensureMigrationsSchemaExists(databaseURL, cfg.Driver, migrationsTable); err != nil {
		return nil, "", err
	}
	databaseURL, err = applyMigrationsTable(databaseURL, cfg.Driver, migrationsTable)
	if err != nil {
		return nil, "", err
	}

	sourceURL, err := resolveMigrationsSourceURL(cfg.Driver, cfg.MigrationsPath)
	if err != nil {
		return nil, "", err
	}

	runner, err := migrate.New(sourceURL, databaseURL)
	if err != nil {
		return nil, "", fmt.Errorf("create migrate runner: %w", err)
	}
	return runner, sourceURL, nil
}

func resolveMigrationsTable(flagValue string) string {
	value := strings.TrimSpace(flagValue)
	if value == "" {
		value = lookupEnv("OPENAUTH_MIGRATE_MIGRATIONS_TABLE")
	}
	if value == "" {
		value = "openauth.schema_migrations"
	}
	return value
}

func applyMigrationsTable(databaseURL string, driver string, table string) (string, error) {
	if strings.ToLower(strings.TrimSpace(driver)) != "postgres" {
		return databaseURL, nil
	}
	spec, err := parseMigrationsTableSpec(table)
	if err != nil {
		return "", err
	}
	if spec.Table == "" {
		return databaseURL, nil
	}

	parsed, err := url.Parse(databaseURL)
	if err != nil {
		return "", fmt.Errorf("parse --database-url: %w", err)
	}

	query := parsed.Query()
	if strings.TrimSpace(query.Get("x-migrations-table")) != "" {
		return databaseURL, nil
	}

	if spec.Schema != "" {
		query.Set("x-migrations-table", fmt.Sprintf("\"%s\".\"%s\"", escapeDoubleQuote(spec.Schema), escapeDoubleQuote(spec.Table)))
		query.Set("x-migrations-table-quoted", "true")
	} else {
		query.Set("x-migrations-table", spec.Table)
	}

	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

type migrationsTableSpec struct {
	Schema string
	Table  string
}

var quotedMigrationsTableRegexp = regexp.MustCompile(`"(.*?)"`)

func parseMigrationsTableSpec(value string) (migrationsTableSpec, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return migrationsTableSpec{}, nil
	}

	if strings.Contains(raw, "\"") {
		parts := quotedMigrationsTableRegexp.FindAllStringSubmatch(raw, -1)
		if len(parts) == 1 {
			if strings.TrimSpace(parts[0][1]) == "" {
				return migrationsTableSpec{}, fmt.Errorf("invalid migrations table %q", value)
			}
			return migrationsTableSpec{Table: parts[0][1]}, nil
		}
		if len(parts) == 2 {
			if strings.TrimSpace(parts[0][1]) == "" || strings.TrimSpace(parts[1][1]) == "" {
				return migrationsTableSpec{}, fmt.Errorf("invalid migrations table %q", value)
			}
			return migrationsTableSpec{
				Schema: parts[0][1],
				Table:  parts[1][1],
			}, nil
		}

		return migrationsTableSpec{}, fmt.Errorf("invalid migrations table %q: expected table or schema.table", value)
	}

	parts := strings.Split(raw, ".")
	switch len(parts) {
	case 1:
		if strings.TrimSpace(parts[0]) == "" {
			return migrationsTableSpec{}, fmt.Errorf("invalid migrations table %q", value)
		}
		return migrationsTableSpec{Table: parts[0]}, nil
	case 2:
		if strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return migrationsTableSpec{}, fmt.Errorf("invalid migrations table %q", value)
		}
		return migrationsTableSpec{
			Schema: parts[0],
			Table:  parts[1],
		}, nil
	default:
		return migrationsTableSpec{}, fmt.Errorf("invalid migrations table %q: expected table or schema.table", value)
	}
}

func ensureMigrationsSchemaExists(databaseURL string, driver string, table string) error {
	if strings.ToLower(strings.TrimSpace(driver)) != "postgres" {
		return nil
	}

	spec, err := parseMigrationsTableSpec(table)
	if err != nil {
		return err
	}
	if spec.Schema == "" {
		return nil
	}

	parsedURL, err := url.Parse(databaseURL)
	if err != nil {
		return fmt.Errorf("parse --database-url: %w", err)
	}
	sanitized := migrate.FilterCustomQuery(parsedURL)

	db, err := sql.Open("postgres", sanitized.String())
	if err != nil {
		return fmt.Errorf("open database for schema bootstrap: %w", err)
	}
	defer db.Close()

	query := fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", pq.QuoteIdentifier(spec.Schema))
	if _, err := db.Exec(query); err != nil {
		return fmt.Errorf("ensure migrations schema %q exists: %w", spec.Schema, err)
	}

	return nil
}

func escapeDoubleQuote(value string) string {
	return strings.ReplaceAll(value, `"`, `""`)
}

func resolveMigrationsSourceURL(driver string, migrationsPath string) (string, error) {
	normalizedDriver := strings.ToLower(strings.TrimSpace(driver))
	if normalizedDriver == "" {
		normalizedDriver = "postgres"
	}

	if normalizedDriver != "postgres" {
		return "", fmt.Errorf("unsupported --driver %q: only postgres is currently supported by CLI runner", normalizedDriver)
	}

	pathOrURL := strings.TrimSpace(migrationsPath)
	if pathOrURL == "" {
		pathOrURL = "pkg/storage/postgres/migrations"
	}

	if strings.Contains(pathOrURL, "://") {
		return pathOrURL, nil
	}

	absPath, err := filepath.Abs(pathOrURL)
	if err != nil {
		return "", fmt.Errorf("resolve migrations path %q: %w", pathOrURL, err)
	}

	return "file://" + filepath.ToSlash(absPath), nil
}

func closeMigrationRunner(runner *migrate.Migrate) error {
	if runner == nil {
		return nil
	}

	sourceErr, databaseErr := runner.Close()
	return errors.Join(sourceErr, databaseErr)
}

func isNoChangeBoundaryError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, migrate.ErrNoChange) {
		return true
	}

	// golang-migrate returns bare os.ErrNotExist when a step command
	// reaches the migration boundary (already at latest/earliest version).
	return err == os.ErrNotExist
}

func isDroppedMigrationsTableError(err error, migrationsTable string) bool {
	var dbErr *migratedatabase.Error
	if !errors.As(err, &dbErr) || dbErr == nil {
		return false
	}

	query := strings.TrimSpace(string(dbErr.Query))
	if query == "" || !strings.HasPrefix(strings.ToUpper(query), "TRUNCATE ") {
		return false
	}

	spec, parseErr := parseMigrationsTableSpec(migrationsTable)
	if parseErr != nil || spec.Table == "" {
		return false
	}

	target := pq.QuoteIdentifier(spec.Table)
	if spec.Schema != "" {
		target = pq.QuoteIdentifier(spec.Schema) + "." + target
	}
	if !strings.Contains(query, target) {
		return false
	}

	var pqErr *pq.Error
	if errors.As(dbErr.OrigErr, &pqErr) && string(pqErr.Code) == "3F000" {
		return true
	}

	return strings.Contains(strings.ToLower(dbErr.Error()), "schema") &&
		strings.Contains(strings.ToLower(dbErr.Error()), "does not exist")
}
