package authz

import (
	"context"
	"testing"
)

func aliceID() Identity {
	return Identity{Issuer: "iss", Subject: "alice", DisplayName: "Alice", Email: "a@example.com", EmailVerified: true}
}

func TestResolveNoRoles(t *testing.T) {
	r := &Resolver{Store: newSQLiteTestStore(t), Module: "faq"}
	p, err := r.Resolve(context.Background(), aliceID())
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("principal = nil, want an authenticated principal with no roles")
	}
	if p.Subject != "alice" || p.DisplayName != "Alice" || p.Email != "a@example.com" {
		t.Errorf("identity fields not threaded: %+v", p)
	}
	if !p.EmailVerified {
		t.Error("EmailVerified not threaded from Identity to Principal")
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

	r := &Resolver{Store: st, Module: "faq"}
	p, err := r.Resolve(context.Background(), aliceID())
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

	r := &Resolver{Store: st, Module: "faq"}
	p, err := r.Resolve(context.Background(), aliceID())
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

func TestResolveStoreError(t *testing.T) {
	r := &Resolver{Store: errStore{}, Module: "faq"}
	if _, err := r.Resolve(context.Background(), aliceID()); err == nil {
		t.Error("expected error to propagate from the store")
	}
}

// errStore is a Store whose reads always fail, to exercise error propagation.
type errStore struct{}

func (errStore) Roles(context.Context, string, string, string) ([]string, error) {
	return nil, context.DeadlineExceeded
}
func (errStore) Grant(context.Context, Grant) error                           { return nil }
func (errStore) Revoke(context.Context, string, string, string, string) error { return nil }
func (errStore) Holders(context.Context, string) ([]Holding, bool, error) {
	return nil, false, nil
}
