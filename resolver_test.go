package authz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeSource struct {
	id  *Identity
	err error
}

func (f fakeSource) Identify(*http.Request) (*Identity, error) { return f.id, f.err }

func req() *http.Request { return httptest.NewRequest("GET", "/", nil) }

func TestResolveNilSource(t *testing.T) {
	r := &Resolver{Store: newSQLiteTestStore(t)}
	p, err := r.Resolve(context.Background(), req())
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Errorf("principal = %+v, want nil for unconfigured source", p)
	}
}

func TestResolveAnonymous(t *testing.T) {
	r := &Resolver{Source: fakeSource{id: nil}, Store: newSQLiteTestStore(t)}
	p, err := r.Resolve(context.Background(), req())
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Errorf("principal = %+v, want nil for anonymous request", p)
	}
}

func TestResolveInvalidCredentialPropagates(t *testing.T) {
	wantErr := errors.New("bad token")
	r := &Resolver{Source: fakeSource{err: wantErr}, Store: newSQLiteTestStore(t)}
	_, err := r.Resolve(context.Background(), req())
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

func TestResolveAuthenticatedNoRoles(t *testing.T) {
	id := &Identity{Issuer: "iss", Subject: "alice", DisplayName: "Alice", Email: "a@example.com"}
	r := &Resolver{Source: fakeSource{id: id}, Store: newSQLiteTestStore(t), Module: "faq"}
	p, err := r.Resolve(context.Background(), req())
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("principal = nil, want authenticated principal with no roles")
	}
	if p.Subject != "alice" || p.DisplayName != "Alice" || p.Email != "a@example.com" {
		t.Errorf("identity fields not threaded: %+v", p)
	}
	if len(p.Roles) != 0 {
		t.Errorf("roles = %v, want empty", p.Roles)
	}
	if p.HasRole("admin") {
		t.Error("HasRole(admin) = true, want false")
	}
}

func TestResolveWithRoles(t *testing.T) {
	st := newSQLiteTestStore(t)
	mustGrant(t, st, Grant{Issuer: "iss", Subject: "alice", Module: "faq", Role: "admin", GrantedBy: "cli:test"})

	id := &Identity{Issuer: "iss", Subject: "alice"}
	r := &Resolver{Source: fakeSource{id: id}, Store: st, Module: "faq"}
	p, err := r.Resolve(context.Background(), req())
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasRole("admin") {
		t.Errorf("roles = %v, want admin present", p.Roles)
	}
}

func TestResolveModuleScoping(t *testing.T) {
	st := newSQLiteTestStore(t)
	mustGrant(t, st, Grant{Issuer: "iss", Subject: "alice", Module: "", Role: "super", GrantedBy: "cli:test"})
	mustGrant(t, st, Grant{Issuer: "iss", Subject: "alice", Module: "sf", Role: "sfonly", GrantedBy: "cli:test"})

	id := &Identity{Issuer: "iss", Subject: "alice"}
	r := &Resolver{Source: fakeSource{id: id}, Store: st, Module: "faq"}
	p, err := r.Resolve(context.Background(), req())
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasRole("super") {
		t.Error("global role 'super' should surface in faq-scoped resolve")
	}
	if p.HasRole("sfonly") {
		t.Error("sf-scoped role must not surface in faq-scoped resolve")
	}
}
