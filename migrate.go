package authz

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	pgmig "github.com/infodancer/authz/migrations/postgres"
	sqlitemig "github.com/infodancer/authz/migrations/sqlite"
	"github.com/pressly/goose/v3"
)

// migrationsTable is authz's dedicated goose version table. Distinct from
// the default goose_db_version so the module's migration history does not
// collide with the host application's own goose tree when both share a
// database.
const migrationsTable = "authz_goose_db_version"

// MigratePostgres applies the embedded PostgreSQL migrations against db.
// Safe to call repeatedly; goose tracks applied versions in
// authz_goose_db_version. The caller owns db and its driver registration
// (typically the pgx stdlib driver).
func MigratePostgres(ctx context.Context, db *sql.DB) error {
	return runMigrations(ctx, db, goose.DialectPostgres, pgmig.FS)
}

// MigrateSQLite applies the embedded SQLite migrations against db. Safe to
// call repeatedly. The caller owns db and its driver registration
// (typically modernc.org/sqlite).
func MigrateSQLite(ctx context.Context, db *sql.DB) error {
	return runMigrations(ctx, db, goose.DialectSQLite3, sqlitemig.FS)
}

func runMigrations(ctx context.Context, db *sql.DB, d goose.Dialect, fsys fs.FS) error {
	p, err := goose.NewProvider(d, db, fsys,
		goose.WithTableName(migrationsTable),
		goose.WithLogger(goose.NopLogger()),
	)
	if err != nil {
		return fmt.Errorf("authz: goose provider: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("authz: goose up: %w", err)
	}
	return nil
}
