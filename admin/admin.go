package admin

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

const JWKS_ENDPOINT = "http://member-jwt.s3-website-us-east-1.amazonaws.com/"
const ISSUER = "https://api.memberstack.com"

type Options struct {
	JWKSEndpoint     string
	Issuer           string
	MemberstackAppId string
}

type MemberstackAdmin struct {
	Options          Options
	httpJwksResponse string // TODO: Best way to memoize?
	jwtParser        jwt.Parser
	jwksKeyfunc      keyfunc.Keyfunc
}

func (a MemberstackAdmin) FetchJwks() string {
	slog.Info("Fetching JWKS...", "url", a.Options.JWKSEndpoint)
	res, err := http.Get(a.Options.JWKSEndpoint)
	if err != nil {
		panic("Unable to HTTP GET JWKS")
	}
	defer res.Body.Close()

	buf, err := io.ReadAll(res.Body)
	if err != nil {
		panic("Unable to read JWKS response body to byte array")
	}

	if res.StatusCode != http.StatusOK {
		slog.Error("Non-200 status code", "body", buf)
		panic("Non-200 status code from JWKS endpoint")
	}
	// TODO: check response encoding?
	body := strings.TrimSpace(string(buf))
	return body
}

func (a *MemberstackAdmin) HttpJwksResponse() string {
	// TODO: take advantage of jwkset's own HTTP refreshing goroutine features
	if a.httpJwksResponse == "" {
		a.httpJwksResponse = a.FetchJwks()
	}
	return a.httpJwksResponse
}

func (a *MemberstackAdmin) JwksKeyfunc() keyfunc.Keyfunc {
	if a.jwksKeyfunc == nil {
		slog.Info("No keyfunc cached. Getting it now")
		k, err := keyfunc.NewJWKSetJSON(json.RawMessage(a.HttpJwksResponse()))
		if err != nil {
			slog.Error("Failed to create a keyfunc.Keyfunc", "error", err)
			panic(err)
		}
		a.jwksKeyfunc = k
	}
	return a.jwksKeyfunc
}

func (a *MemberstackAdmin) VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := a.jwtParser.Parse(tokenString, a.JwksKeyfunc().Keyfunc)
	return token, err
}

func NewMemberstackAdmin(o Options) MemberstackAdmin {
	if o.Issuer == "" {
		o.Issuer = ISSUER
	}
	if o.JWKSEndpoint == "" {
		o.JWKSEndpoint = JWKS_ENDPOINT
	}

	ma := MemberstackAdmin{Options: o}

	jwtParserOpts := []jwt.ParserOption{jwt.WithIssuer(o.Issuer)}
	if o.MemberstackAppId != "" {
		jwtParserOpts = append(jwtParserOpts, jwt.WithAudience(o.MemberstackAppId))
	}
	// TODO: Should my jwtParser also be a pointer?
	ma.jwtParser = *jwt.NewParser(jwtParserOpts...)

	return ma
}
