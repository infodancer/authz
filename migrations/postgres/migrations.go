// Package postgres embeds the PostgreSQL migration files for authz.
package postgres

import "embed"

// FS holds the embedded PostgreSQL migration files.
//
//go:embed *.sql
var FS embed.FS
