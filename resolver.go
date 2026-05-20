package authz

import (
	"context"
	"fmt"
	"net/http"
	"slices"
)

// Identity is the authenticated subject extracted from a request by an
// [IdentitySource]. It carries identity only — never roles. (issuer,
// subject) is the stable key into the role store; DisplayName and Email
// are presentation data the host may surface.
type Identity struct {
	Issuer      string
	Subject     string
	DisplayName string
	Email       string
}

// IdentitySource extracts an authenticated [Identity] from an HTTP
// request. Implementations adapt whatever auth-N mechanism the host runs:
// an OIDC cookie/JWT client, mutual TLS, an API-key lookup, and so on.
//
// Identify returns (nil, nil) for an anonymous request and (nil, err) for
// a present-but-invalid credential. The latter signals the host to
// produce 401; the former is the normal logged-out case and read paths
// should remain open to it.
type IdentitySource interface {
	Identify(r *http.Request) (*Identity, error)
}

// Principal is an authenticated identity together with the roles granted
// to it, scoped to the resolver's module. A nil *Principal from
// [Resolver.Resolve] means anonymous.
type Principal struct {
	Issuer      string
	Subject     string
	DisplayName string
	Email       string
	Roles       []string
}

// HasRole reports whether the principal holds role.
func (p *Principal) HasRole(role string) bool {
	return slices.Contains(p.Roles, role)
}

// Resolver turns an HTTP request into a [Principal] by combining an
// [IdentitySource] (who is this?) with a [Store] (what may they do?).
//
// Module scopes the role lookup: a resolver with Module "faq" sees grants
// made with module "faq" plus all global grants (module ""). An empty
// Module yields a global-only checker.
type Resolver struct {
	Source IdentitySource
	Store  Store
	Module string
}

// Resolve identifies the request's subject and loads its roles.
//
// Returns (nil, nil) for anonymous requests and when Source is nil (an
// unconfigured resolver treats everyone as anonymous rather than
// erroring). A present-but-invalid credential from the IdentitySource
// propagates as (nil, err).
func (r *Resolver) Resolve(ctx context.Context, req *http.Request) (*Principal, error) {
	if r.Source == nil {
		return nil, nil
	}
	id, err := r.Source.Identify(req)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, nil
	}
	roles, err := r.Store.Roles(ctx, id.Issuer, id.Subject, r.Module)
	if err != nil {
		return nil, fmt.Errorf("authz: resolve roles: %w", err)
	}
	return &Principal{
		Issuer:      id.Issuer,
		Subject:     id.Subject,
		DisplayName: id.DisplayName,
		Email:       id.Email,
		Roles:       roles,
	}, nil
}
