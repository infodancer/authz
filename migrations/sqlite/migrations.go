// Package sqlite embeds the SQLite migration files for authz.
package sqlite

import "embed"

// FS holds the embedded SQLite migration files.
//
//go:embed *.sql
var FS embed.FS
