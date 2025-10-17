//go:build integration

package test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/auth"
	"golang.org/x/oauth2"
)

func tokenSource(t *testing.T) oauth2.TokenSource {
	t.Helper()
	check := func(err error) {
		if err != nil {
			t.Fatalf("token source error: %v", err)
		}
	}

	err := os.MkdirAll("assets", 0o755)
	check(err)

	token := new(oauth2.Token)
	tokenData, err := os.ReadFile("./assets/token.tok")
	if err == nil {
		_ = json.Unmarshal(tokenData, token)
	} else {
		token, err = auth.RequestLiveToken()
		check(err)
	}
	src := auth.RefreshTokenSource(token)
	_, err = src.Token()
	if err != nil {
		token, err = auth.RequestLiveToken()
		check(err)
		src = auth.RefreshTokenSource(token)
	}
	tok, _ := src.Token()
	b, _ := json.Marshal(tok)
	_ = os.WriteFile("./assets/token.tok", b, 0o644)
	return src
}

func TestTokenSource(t *testing.T) {
	src := tokenSource(t)
	if src == nil {
		t.Fatalf("expected token source")
	}
}
