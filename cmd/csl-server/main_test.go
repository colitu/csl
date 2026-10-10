package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityStreamLimitsRelease(t *testing.T) {
	limits := newIdentityStreamLimits(2)
	first, releaseFirst := limits.acquire("alice")
	second, releaseSecond := limits.acquire("alice")
	other, releaseOther := limits.acquire("bob")
	if first != second || first == other {
		t.Fatal("user stream limits were not shared by identity")
	}
	releaseFirst()
	if limits.entries["alice"] == nil {
		t.Fatal("removed a limit while another session still uses it")
	}
	releaseSecond()
	releaseOther()
	if len(limits.entries) != 0 {
		t.Fatalf("retained %d unused user limits", len(limits.entries))
	}
}

func TestIdentityProviderReload(t *testing.T) {
	credential := []byte("a-long-device-credential")
	sum := sha256.Sum256(credential)
	key := hex.EncodeToString(sum[:])
	p := &identityProvider{entries: map[string]string{key: "alice"}}
	if user, err := p.authenticate(credential); err != nil || user != "alice" {
		t.Fatalf("initial identity = %q, %v", user, err)
	}
	p.update(nil, errors.New("invalid update"))
	if _, err := p.authenticate(credential); err == nil {
		t.Fatal("invalid update accepted a new session")
	}
	p.update(map[string]string{}, nil)
	if _, err := p.authenticate(credential); err == nil {
		t.Fatal("revoked credential accepted a new session")
	}
}

func TestIdentityFileValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities.json")
	sum := sha256.Sum256([]byte("a-long-device-credential"))
	key := hex.EncodeToString(sum[:])
	if err := os.WriteFile(path, []byte(`{"`+key+`":"alice"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	identities, err := loadIdentities(path)
	if err != nil || identities[key] != "alice" {
		t.Fatalf("valid identities = %v, %v", identities, err)
	}
	if err := os.WriteFile(path, []byte(`{"bad hash":"alice"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentities(path); err == nil {
		t.Fatal("invalid identity hash accepted")
	}
}
