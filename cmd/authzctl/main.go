// Command authzctl manages the authz role store from the shell. It is the
// canonical bootstrap path: granting the first global admin before any
// admin UI exists, and the recovery path if a host's grant flow misbehaves.
//
// Usage:
//
//	authzctl --driver postgres --dsn $DATABASE_URL <command> [args]
//
// Commands:
//
//	grant   ISSUER SUBJECT ROLE [--module M] [--by WHO]
//	revoke  ISSUER SUBJECT ROLE [--module M]
//	roles   ISSUER SUBJECT [--module M]
//	holders ROLE
//	migrate
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strings"
	"text/tabwriter"

	"github.com/infodancer/authz"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

func main() {
	top := flag.NewFlagSet("authzctl", flag.ExitOnError)
	driver := top.String("driver", "postgres", "database driver: postgres or sqlite")
	dsn := top.String("dsn", "", "database connection string (or path for sqlite)")
	top.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
	}
	_ = top.Parse(os.Args[1:])

	args := top.Args()
	if len(args) == 0 {
		top.Usage()
		os.Exit(2)
	}
	if *dsn == "" {
		fatal("--dsn is required")
	}

	cmd, rest := args[0], args[1:]
	if err := run(*driver, *dsn, cmd, rest); err != nil {
		fatal(err.Error())
	}
}

func run(driver, dsn, cmd string, args []string) error {
	ctx := context.Background()
	db, err := open(driver, dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	switch cmd {
	case "migrate":
		if err := migrateFor(ctx, driver, db); err != nil {
			return err
		}
		fmt.Println("migrations applied")
		return nil

	case "grant":
		fs := flag.NewFlagSet("grant", flag.ExitOnError)
		module := fs.String("module", "", "module scope (empty = global)")
		by := fs.String("by", defaultBy(), "granted_by attribution")
		pos, err := parseArgs(fs, args)
		if err != nil {
			return err
		}
		if len(pos) != 3 {
			return fmt.Errorf("grant: want ISSUER SUBJECT ROLE, got %d args", len(pos))
		}
		if err := rejectPadded("issuer", pos[0], "subject", pos[1], "role", pos[2], "module", *module); err != nil {
			return err
		}
		g := authz.Grant{
			Issuer: pos[0], Subject: pos[1], Module: *module,
			Role: pos[2], GrantedBy: *by,
		}
		if err := storeFor(driver, db).Grant(ctx, g); err != nil {
			return err
		}
		fmt.Printf("granted %s to %s/%s in module %q\n", g.Role, g.Issuer, g.Subject, g.Module)
		return nil

	case "revoke":
		fs := flag.NewFlagSet("revoke", flag.ExitOnError)
		module := fs.String("module", "", "module scope (empty = global)")
		pos, err := parseArgs(fs, args)
		if err != nil {
			return err
		}
		if len(pos) != 3 {
			return fmt.Errorf("revoke: want ISSUER SUBJECT ROLE, got %d args", len(pos))
		}
		if err := rejectPadded("issuer", pos[0], "subject", pos[1], "role", pos[2], "module", *module); err != nil {
			return err
		}
		if err := storeFor(driver, db).Revoke(ctx, pos[0], pos[1], *module, pos[2]); err != nil {
			return err
		}
		fmt.Printf("revoked %s from %s/%s in module %q\n", pos[2], pos[0], pos[1], *module)
		return nil

	case "roles":
		fs := flag.NewFlagSet("roles", flag.ExitOnError)
		module := fs.String("module", "", "module scope (empty = global only)")
		pos, err := parseArgs(fs, args)
		if err != nil {
			return err
		}
		if len(pos) != 2 {
			return fmt.Errorf("roles: want ISSUER SUBJECT, got %d args", len(pos))
		}
		if err := rejectPadded("issuer", pos[0], "subject", pos[1], "module", *module); err != nil {
			return err
		}
		roles, err := storeFor(driver, db).Roles(ctx, pos[0], pos[1], *module)
		if err != nil {
			return err
		}
		for _, r := range roles {
			fmt.Println(r)
		}
		return nil

	case "holders":
		fs := flag.NewFlagSet("holders", flag.ExitOnError)
		pos, err := parseArgs(fs, args)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return fmt.Errorf("holders: want ROLE, got %d args", len(pos))
		}
		if err := rejectPadded("role", pos[0]); err != nil {
			return err
		}
		holdings, capped, err := storeFor(driver, db).Holders(ctx, pos[0])
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "ISSUER\tSUBJECT\tMODULE\tGRANTED_AT\tGRANTED_BY")
		for _, h := range holdings {
			module := h.Module
			if module == "" {
				module = "(global)"
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				h.Issuer, h.Subject, module, h.GrantedAt.Format("2006-01-02T15:04:05Z07:00"), h.GrantedBy)
		}
		_ = w.Flush()
		if capped {
			fmt.Fprintln(os.Stderr, "warning: result truncated at 10000 rows")
		}
		return nil

	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// parseArgs parses fs while allowing flags and positional arguments to be
// interspersed. The stdlib flag package stops at the first non-flag token;
// this loop resumes parsing after each positional so "grant ISS SUB ROLE
// --module faq" works as well as "grant --module faq ISS SUB ROLE".
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// rejectPadded errors if any value has leading or trailing whitespace.
// authzctl is the one place issuer/subject/role/module are entered by a
// human (often pasted), and a stray space or newline would store a key
// that never byte-matches the value an IdP issues at lookup time — a
// grant that silently does nothing. Args come in name, value pairs.
func rejectPadded(pairs ...string) error {
	for i := 0; i+1 < len(pairs); i += 2 {
		name, v := pairs[i], pairs[i+1]
		if strings.TrimSpace(v) != v {
			return fmt.Errorf("%s %q has leading or trailing whitespace", name, v)
		}
	}
	return nil
}

func open(driver, dsn string) (*sql.DB, error) {
	switch driver {
	case "postgres":
		return sql.Open("pgx", dsn)
	case "sqlite":
		return sql.Open("sqlite", dsn)
	default:
		return nil, fmt.Errorf("unknown driver %q (want postgres or sqlite)", driver)
	}
}

func storeFor(driver string, db *sql.DB) authz.Store {
	if driver == "sqlite" {
		return authz.NewSQLiteStore(db)
	}
	return authz.NewPostgresStore(db)
}

func migrateFor(ctx context.Context, driver string, db *sql.DB) error {
	if driver == "sqlite" {
		return authz.MigrateSQLite(ctx, db)
	}
	return authz.MigratePostgres(ctx, db)
}

func defaultBy() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return "cli:" + u.Username
	}
	return "cli:unknown"
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "authzctl: "+msg)
	os.Exit(1)
}

const usage = `authzctl manages the authz role store.

Usage:
  authzctl --driver <postgres|sqlite> --dsn <conn> <command> [args]

Commands:
  grant   ISSUER SUBJECT ROLE [--module M] [--by WHO]   grant a role
  revoke  ISSUER SUBJECT ROLE [--module M]              revoke a role
  roles   ISSUER SUBJECT [--module M]                   list a subject's roles
  holders ROLE                                          list grants of a role
  migrate                                               apply schema migrations

Global flags:
  --driver  database driver (default postgres)
  --dsn     connection string, or file path for sqlite
`
