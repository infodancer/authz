package authz

import (
	"context"
	"fmt"
	"slices"
)

// Identity is an authenticated subject, as resolved by the host from
// whatever auth-N mechanism it runs (an OIDC cookie/JWT, mutual TLS, an
// API key, ...). It carries identity only — never roles. (issuer,
// subject) is the stable key into the role store; DisplayName and Email
// are presentation data the host may surface.
//
// authz does not extract Identity from a request — it has no knowledge of
// HTTP. The host validates the request and constructs the Identity, then
// asks authz what that identity may do.
type Identity struct {
	Issuer      string
	Subject     string
	DisplayName string
	Email       string
}

// Principal is an authenticated identity together with the roles granted
// to it, scoped to the resolver's module.
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

// Resolver loads the roles for an [Identity] from a [Store], scoped to a
// module. A resolver with Module "faq" sees grants made with module "faq"
// plus all global grants (module ""). An empty Module yields a
// global-only checker.
//
// The host is responsible for authentication: turn a request into an
// Identity (anonymous requests never reach Resolve), then call Resolve to
// load that identity's roles. Keeping the request out of authz is what
// lets the package stay free of any HTTP or auth-N dependency.
type Resolver struct {
	Store  Store
	Module string
}

// Resolve loads id's roles, scoped to the resolver's module, and returns
// a [Principal]. An authenticated identity with no grants yields a
// Principal with an empty Roles slice, not an error.
func (r *Resolver) Resolve(ctx context.Context, id Identity) (*Principal, error) {
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
