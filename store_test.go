package authz

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/infodancer/authz/migrate"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	_ "modernc.org/sqlite"
)

// eachBackend runs fn against a freshly-migrated store on each supported
// backend, so every behavioral test exercises both PostgreSQL and SQLite.
func eachBackend(t *testing.T, fn func(t *testing.T, st Store)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) {
		fn(t, newSQLiteTestStore(t))
	})
	t.Run("postgres", func(t *testing.T) {
		fn(t, newPostgresTestStore(t))
	})
}

func newSQLiteTestStore(t *testing.T) Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authz_test.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer.
	t.Cleanup(func() { _ = db.Close() })
	if err := migrate.SQLite(context.Background(), db); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	return NewSQLiteStore(db)
}

func newPostgresTestStore(t *testing.T) Store {
	t.Helper()
	ctx := context.Background()
	c, err := postgres.Run(ctx, "postgres:17-alpine",
		postgres.WithDatabase("authz"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open pgx: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := migrate.Postgres(ctx, db); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	return NewPostgresStore(db)
}

func mustGrant(t *testing.T, st Store, g Grant) {
	t.Helper()
	if err := st.Grant(context.Background(), g); err != nil {
		t.Fatalf("grant %+v: %v", g, err)
	}
}

func TestGrantAndRoles(t *testing.T) {
	eachBackend(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		mustGrant(t, st, Grant{Issuer: "iss", Subject: "alice", Module: "faq", Role: "admin", GrantedBy: "cli:test"})

		roles, err := st.Roles(ctx, "iss", "alice", "faq")
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(roles, []string{"admin"}) {
			t.Errorf("roles = %v, want [admin]", roles)
		}
	})
}

func TestGlobalRoleVisibleInAnyModule(t *testing.T) {
	eachBackend(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		mustGrant(t, st, Grant{Issuer: "iss", Subject: "alice", Module: "", Role: "admin", GrantedBy: "cli:test"})

		// A global grant (module "") surfaces under any module lookup.
		roles, err := st.Roles(ctx, "iss", "alice", "faq")
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(roles, []string{"admin"}) {
			t.Errorf("roles = %v, want [admin] (global should surface in module lookup)", roles)
		}
	})
}

func TestModuleScopingIsolation(t *testing.T) {
	eachBackend(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		mustGrant(t, st, Grant{Issuer: "iss", Subject: "alice", Module: "sf", Role: "admin", GrantedBy: "cli:test"})

		// An sf-scoped grant must not surface in a faq lookup.
		roles, err := st.Roles(ctx, "iss", "alice", "faq")
		if err != nil {
			t.Fatal(err)
		}
		if len(roles) != 0 {
			t.Errorf("roles = %v, want empty (sf grant must not leak into faq)", roles)
		}
	})
}

func TestRolesDeduped(t *testing.T) {
	eachBackend(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		mustGrant(t, st, Grant{Issuer: "iss", Subject: "alice", Module: "", Role: "admin", GrantedBy: "cli:test"})
		mustGrant(t, st, Grant{Issuer: "iss", Subject: "alice", Module: "faq", Role: "admin", GrantedBy: "cli:test"})

		// Same role granted both globally and module-scoped: lookup returns it once.
		roles, err := st.Roles(ctx, "iss", "alice", "faq")
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(roles, []string{"admin"}) {
			t.Errorf("roles = %v, want [admin] (deduped)", roles)
		}
	})
}

func TestGrantIdempotentPreservesOriginal(t *testing.T) {
	eachBackend(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		mustGrant(t, st, Grant{Issuer: "iss", Subject: "alice", Module: "faq", Role: "admin", GrantedBy: "first"})
		// Re-grant with a different granted_by; DO NOTHING should keep the original row.
		mustGrant(t, st, Grant{Issuer: "iss", Subject: "alice", Module: "faq", Role: "admin", GrantedBy: "second"})

		holdings, capped, err := st.Holders(ctx, "admin")
		if err != nil {
			t.Fatal(err)
		}
		if capped {
			t.Fatal("unexpected cap on a tiny table")
		}
		if len(holdings) != 1 {
			t.Fatalf("holders = %d rows, want 1 (re-grant must not duplicate)", len(holdings))
		}
		if holdings[0].GrantedBy != "first" {
			t.Errorf("granted_by = %q, want first (re-grant must not overwrite)", holdings[0].GrantedBy)
		}
		if holdings[0].GrantedAt.IsZero() {
			t.Error("granted_at is zero; expected a populated timestamp")
		}
	})
}

func TestRevoke(t *testing.T) {
	eachBackend(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		mustGrant(t, st, Grant{Issuer: "iss", Subject: "alice", Module: "faq", Role: "admin", GrantedBy: "cli:test"})

		if err := st.Revoke(ctx, "iss", "alice", "faq", "admin"); err != nil {
			t.Fatal(err)
		}
		roles, err := st.Roles(ctx, "iss", "alice", "faq")
		if err != nil {
			t.Fatal(err)
		}
		if len(roles) != 0 {
			t.Errorf("roles = %v after revoke, want empty", roles)
		}
	})
}

func TestRevokeNonexistentIsNoOp(t *testing.T) {
	eachBackend(t, func(t *testing.T, st Store) {
		if err := st.Revoke(context.Background(), "iss", "ghost", "faq", "admin"); err != nil {
			t.Errorf("revoke of nonexistent tuple errored: %v", err)
		}
	})
}

func TestRolesEmptyForUnknownUser(t *testing.T) {
	eachBackend(t, func(t *testing.T, st Store) {
		roles, err := st.Roles(context.Background(), "iss", "nobody", "faq")
		if err != nil {
			t.Fatal(err)
		}
		if len(roles) != 0 {
			t.Errorf("roles = %v, want empty for unknown user", roles)
		}
	})
}

func TestHolders(t *testing.T) {
	eachBackend(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		mustGrant(t, st, Grant{Issuer: "iss", Subject: "alice", Module: "", Role: "admin", GrantedBy: "cli:test"})
		mustGrant(t, st, Grant{Issuer: "iss", Subject: "bob", Module: "faq", Role: "admin", GrantedBy: "cli:test"})
		mustGrant(t, st, Grant{Issuer: "iss", Subject: "carol", Module: "faq", Role: "editor", GrantedBy: "cli:test"})

		holdings, capped, err := st.Holders(ctx, "admin")
		if err != nil {
			t.Fatal(err)
		}
		if capped {
			t.Fatal("unexpected cap")
		}
		if len(holdings) != 2 {
			t.Fatalf("admin holders = %d, want 2", len(holdings))
		}
		// Ordered by (issuer, subject, module): alice before bob.
		if holdings[0].Subject != "alice" || holdings[1].Subject != "bob" {
			t.Errorf("holder order = [%s, %s], want [alice, bob]", holdings[0].Subject, holdings[1].Subject)
		}
		if holdings[0].Module != "" || holdings[1].Module != "faq" {
			t.Errorf("holder modules = [%q, %q], want [\"\", faq]", holdings[0].Module, holdings[1].Module)
		}
	})
}

func TestGrantValidation(t *testing.T) {
	eachBackend(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		cases := map[string]Grant{
			"empty issuer":     {Issuer: "", Subject: "alice", Role: "admin", GrantedBy: "cli:test"},
			"empty subject":    {Issuer: "iss", Subject: "", Role: "admin", GrantedBy: "cli:test"},
			"empty role":       {Issuer: "iss", Subject: "alice", Role: "", GrantedBy: "cli:test"},
			"empty granted_by": {Issuer: "iss", Subject: "alice", Role: "admin", GrantedBy: ""},
		}
		for name, g := range cases {
			if err := st.Grant(ctx, g); err == nil {
				t.Errorf("grant with %s should error", name)
			}
		}

		// An empty module is valid — it's a global grant.
		if err := st.Grant(ctx, Grant{Issuer: "iss", Subject: "alice", Module: "", Role: "admin", GrantedBy: "cli:test"}); err != nil {
			t.Errorf("grant with empty module (global) should succeed, got %v", err)
		}
	})
}
