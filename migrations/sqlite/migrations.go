// Package sqlite embeds the SQLite migration files for authz.
package sqlite

import "embed"

//go:embed *.sql
var FS embed.FS
