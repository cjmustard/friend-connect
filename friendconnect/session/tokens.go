package session

import (
	"context"
	"net/http"

	"github.com/df-mc/go-xsapi"

	"github.com/cjmustard/friend-connect/friendconnect/xbox"
)

type accountTokenSource struct {
	acct *xbox.Account
}

func (s accountTokenSource) Token() (xsapi.Token, error) {
	tok, err := s.acct.Token(context.Background(), xbox.RelyingPartyXboxLive)
	if err != nil {
		return nil, err
	}
	return xsapiToken{tok: tok}, nil
}

type xsapiToken struct {
	tok *xbox.Token
}

func (t xsapiToken) SetAuthHeader(req *http.Request) {
	req.Header.Set("Authorization", t.tok.Header)
}

func (t xsapiToken) String() string {
	return t.tok.Header
}

func (t xsapiToken) DisplayClaims() xsapi.DisplayClaims {
	return xsapi.DisplayClaims{
		GamerTag: t.tok.Gamertag,
		XUID:     t.tok.XUID,
		UserHash: t.tok.UserHash,
	}
}
