// Package authz is a small authorization layer for Go web applications.
//
// It provides a role store keyed on (issuer, subject, module, role) and a
// resolver that maps an authenticated identity into the roles granted to
// it. authz is deliberately decoupled from authentication: roles are never
// read from JWT claims, and the package has no knowledge of HTTP. The host
// validates each request and constructs an [Identity]; authz answers what
// that identity may do.
//
// See DESIGN.md at the repository root for the full rationale.
package authz

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// holdersLimit caps the number of rows [Store.Holders] returns. It is a
// misuse guard, not a pagination mechanism — realistic role tables hold
// far fewer rows. A caller that hits the cap gets capped=true so it can
// warn rather than silently truncate.
const holdersLimit = 10000

// Grant is a single role assignment to be written by [Store.Grant].
//
// Module is the URL-safe name of the consuming module ("faq", "blog") or
// the empty string for a global grant that applies across every module.
// GrantedBy is free-text attribution, conventionally "cli:<operator>" or
// "host:<app>:<endpoint>".
type Grant struct {
	Issuer    string
	Subject   string
	Module    string
	Role      string
	GrantedBy string
}

// Holding is one row of the role table as returned by [Store.Holders],
// used for audit and the authzctl holders command.
type Holding struct {
	Issuer    string
	Subject   string
	Module    string
	Role      string
	GrantedAt time.Time
	GrantedBy string
}

// Store is the persistence contract for role assignments. Implementations
// for PostgreSQL and SQLite ship with the module; both satisfy the same
// behavioral test suite.
type Store interface {
	// Roles returns every role granted to (issuer, subject) whose module
	// is either "" (global) or equal to the requested module. The result
	// is deduplicated and sorted. An authenticated user with no grants
	// yields an empty slice, not an error.
	Roles(ctx context.Context, issuer, subject, module string) ([]string, error)

	// Grant inserts a role assignment. Idempotent: re-granting an existing
	// (issuer, subject, module, role) tuple is a no-op and preserves the
	// original granted_at.
	Grant(ctx context.Context, g Grant) error

	// Revoke hard-deletes a specific (issuer, subject, module, role) tuple.
	// Revoking a tuple that does not exist is a no-op, not an error.
	Revoke(ctx context.Context, issuer, subject, module, role string) error

	// Holders lists every grant of role across all modules, ordered by
	// (issuer, subject, module). At most holdersLimit rows are returned;
	// capped reports whether more rows existed than were returned.
	Holders(ctx context.Context, role string) (holdings []Holding, capped bool, err error)
}

// Per-backend SQL. The two backends differ only in placeholder syntax
// ($1 vs ?); the statements are otherwise identical. These are compile-
// time constants, passed directly to Query/Exec, so the static analyzer
// can confirm the query text is never attacker-influenced — every value
// reaches the database as a bound parameter, never interpolated.
const (
	pgRolesSQL = `SELECT DISTINCT role FROM authz_user_roles
		WHERE issuer = $1 AND subject = $2 AND module IN ('', $3)
		ORDER BY role`
	pgGrantSQL = `INSERT INTO authz_user_roles (issuer, subject, module, role, granted_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (issuer, subject, module, role) DO NOTHING`
	pgRevokeSQL = `DELETE FROM authz_user_roles
		WHERE issuer = $1 AND subject = $2 AND module = $3 AND role = $4`
	pgHoldersSQL = `SELECT issuer, subject, module, role, granted_at, granted_by
		FROM authz_user_roles
		WHERE role = $1
		ORDER BY issuer, subject, module
		LIMIT $2`

	sqliteRolesSQL = `SELECT DISTINCT role FROM authz_user_roles
		WHERE issuer = ? AND subject = ? AND module IN ('', ?)
		ORDER BY role`
	sqliteGrantSQL = `INSERT INTO authz_user_roles (issuer, subject, module, role, granted_by)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (issuer, subject, module, role) DO NOTHING`
	sqliteRevokeSQL = `DELETE FROM authz_user_roles
		WHERE issuer = ? AND subject = ? AND module = ? AND role = ?`
	sqliteHoldersSQL = `SELECT issuer, subject, module, role, granted_at, granted_by
		FROM authz_user_roles
		WHERE role = ?
		ORDER BY issuer, subject, module
		LIMIT ?`
)

type dbStore struct {
	db     *sql.DB
	sqlite bool
}

// NewPostgresStore returns a [Store] backed by a PostgreSQL database. The
// caller opens db with a PostgreSQL driver (typically the pgx stdlib
// driver) and owns its lifecycle. A pgxpool-based host can adapt its pool
// with stdlib.OpenDBFromPool.
func NewPostgresStore(db *sql.DB) Store { return &dbStore{db: db} }

// NewSQLiteStore returns a [Store] backed by a SQLite database. The caller
// opens db with a SQLite driver (typically modernc.org/sqlite) and owns
// its lifecycle.
func NewSQLiteStore(db *sql.DB) Store { return &dbStore{db: db, sqlite: true} }

func (s *dbStore) Roles(ctx context.Context, issuer, subject, module string) ([]string, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if s.sqlite {
		rows, err = s.db.QueryContext(ctx, sqliteRolesSQL, issuer, subject, module)
	} else {
		rows, err = s.db.QueryContext(ctx, pgRolesSQL, issuer, subject, module)
	}
	if err != nil {
		return nil, fmt.Errorf("authz: query roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("authz: scan role: %w", err)
		}
		out = append(out, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authz: roles rows: %w", err)
	}
	return out, nil
}

func (s *dbStore) Grant(ctx context.Context, g Grant) error {
	if g.Role == "" {
		return fmt.Errorf("authz: grant: empty role")
	}
	if g.GrantedBy == "" {
		return fmt.Errorf("authz: grant: empty granted_by")
	}
	var err error
	if s.sqlite {
		_, err = s.db.ExecContext(ctx, sqliteGrantSQL, g.Issuer, g.Subject, g.Module, g.Role, g.GrantedBy)
	} else {
		_, err = s.db.ExecContext(ctx, pgGrantSQL, g.Issuer, g.Subject, g.Module, g.Role, g.GrantedBy)
	}
	if err != nil {
		return fmt.Errorf("authz: grant: %w", err)
	}
	return nil
}

func (s *dbStore) Revoke(ctx context.Context, issuer, subject, module, role string) error {
	var err error
	if s.sqlite {
		_, err = s.db.ExecContext(ctx, sqliteRevokeSQL, issuer, subject, module, role)
	} else {
		_, err = s.db.ExecContext(ctx, pgRevokeSQL, issuer, subject, module, role)
	}
	if err != nil {
		return fmt.Errorf("authz: revoke: %w", err)
	}
	return nil
}

func (s *dbStore) Holders(ctx context.Context, role string) ([]Holding, bool, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if s.sqlite {
		rows, err = s.db.QueryContext(ctx, sqliteHoldersSQL, role, holdersLimit+1)
	} else {
		rows, err = s.db.QueryContext(ctx, pgHoldersSQL, role, holdersLimit+1)
	}
	if err != nil {
		return nil, false, fmt.Errorf("authz: query holders: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Holding
	for rows.Next() {
		var h Holding
		var ts timeScanner
		if err := rows.Scan(&h.Issuer, &h.Subject, &h.Module, &h.Role, &ts, &h.GrantedBy); err != nil {
			return nil, false, fmt.Errorf("authz: scan holder: %w", err)
		}
		h.GrantedAt = ts.t
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("authz: holders rows: %w", err)
	}

	capped := len(out) > holdersLimit
	if capped {
		out = out[:holdersLimit]
	}
	return out, capped, nil
}

// timeScanner accepts both native time.Time (PostgreSQL TIMESTAMPTZ) and
// ISO-8601 strings (SQLite TEXT columns) when scanning granted_at.
type timeScanner struct{ t time.Time }

func (s *timeScanner) Scan(src any) error {
	switch v := src.(type) {
	case time.Time:
		s.t = v
	case string:
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return fmt.Errorf("authz: parse time %q: %w", v, err)
		}
		s.t = t
	case []byte:
		t, err := time.Parse(time.RFC3339, string(v))
		if err != nil {
			return fmt.Errorf("authz: parse time %q: %w", string(v), err)
		}
		s.t = t
	case nil:
		// leave zero value
	default:
		return fmt.Errorf("authz: unexpected time scan type %T", src)
	}
	return nil
}
