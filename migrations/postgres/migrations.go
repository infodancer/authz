// Package postgres embeds the PostgreSQL migration files for authz.
package postgres

import "embed"

//go:embed *.sql
var FS embed.FS
