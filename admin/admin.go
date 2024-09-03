package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

const JWKS_ENDPOINT = "http://member-jwt.s3-website-us-east-1.amazonaws.com/"
const ISSUER = "https://api.memberstack.com"

var (
	ErrBadJwks = errors.New("bad JWKS")
)

type MemberstackJwtClaims struct {
	MemberID string `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`
	IsAdmin  bool   `json:"isAdmin,omitempty"`
	jwt.RegisteredClaims
}

type Options struct {
	HTTPTimeoutSeconds int
	JWKSEndpoint       string
	Issuer             string
	MemberstackAppId   string
}

type MemberstackAdmin struct {
	Options          Options
	httpJwksResponse string // TODO: Best way to memoize?
	jwtParser        jwt.Parser
	jwksKeyfunc      keyfunc.Keyfunc
	httpClient       http.Client
}

func (a *MemberstackAdmin) fetchJwks() (string, error) { // TODO: does it need to be a pointer?
	slog.Info("Fetching JWKS...", "url", a.Options.JWKSEndpoint)
	res, err := a.httpClient.Get(a.Options.JWKSEndpoint)
	if err != nil {
		slog.Error("Unable to HTTP GET JWKS")
		return "", err
	}
	defer res.Body.Close()

	buf, err := io.ReadAll(res.Body)
	if err != nil {
		slog.Error("Unable to read JWKS response body to byte array")
		return "", err
	}

	if res.StatusCode != http.StatusOK {
		slog.Error("Non-200 status code", "body", buf, "status", res.StatusCode)
		return "", fmt.Errorf("Non-200 status code from JWKS endpoint (got %d)", res.StatusCode)
	}
	// TODO: check response encoding?
	body := strings.TrimSpace(string(buf))
	return body, nil
}

func (a *MemberstackAdmin) getHttpJwksResponse() (string, error) {
	// TODO: take advantage of jwkset's own HTTP refreshing goroutine features
	if a.httpJwksResponse == "" {
		jwks, err := a.fetchJwks()
		if err != nil {
			slog.Error("Unable to fetch JWKS: ", "error", err)
			return "", err
		}
		a.httpJwksResponse = jwks
	}
	return a.httpJwksResponse, nil
}

func (a *MemberstackAdmin) getJwksKeyfunc(updateCache bool) (keyfunc.Keyfunc, error) {
	if a.jwksKeyfunc == nil || updateCache {
		slog.Info("No keyfunc cached or updateCache=true. Getting it now")
		jwks, err := a.getHttpJwksResponse()
		if err != nil {
			slog.Error("Failed to get JWKS", "error", err)
			if a.jwksKeyfunc == nil {
				return nil, err
			} else {
				return a.jwksKeyfunc, fmt.Errorf("update cache failed: %w", err)
			}
		}
		k, err := keyfunc.NewJWKSetJSON(json.RawMessage(jwks))
		if err != nil {
			slog.Error("Failed to create a keyfunc.Keyfunc", "error", err)
			if a.jwksKeyfunc == nil {
				return nil, err
			} else {
				return a.jwksKeyfunc, fmt.Errorf("update cache failed: %w", err)
			}
		}
		a.jwksKeyfunc = k
	}
	return a.jwksKeyfunc, nil
}

// GetJwksKeyfunc fetches the JWKS from the HTTP server, parses it into a key
// function [jwt.Parse] understands, and caches it on [MemberstackAdmin].
// Subsequent calls returns the cached value.
func (a *MemberstackAdmin) GetJwksKeyfunc() (keyfunc.Keyfunc, error) {
	return a.getJwksKeyfunc(false)
}

// GetLatestJwksKeyfunc does the same as [MemberstackAdmin.GetJwksKeyfunc] but
// always fetches from the HTTP server, updating the local cache along the way.
func (a *MemberstackAdmin) GetLatestJwksKeyfunc() (keyfunc.Keyfunc, error) {
	return a.getJwksKeyfunc(true)
}

func (a *MemberstackAdmin) VerifyToken(tokenString string) (*jwt.Token, error) {
	k, err := a.GetJwksKeyfunc()
	if err != nil {
		return &jwt.Token{
			Valid: false,
		}, fmt.Errorf("%w: %w", ErrBadJwks, err)
	}
	token, err := a.jwtParser.ParseWithClaims(tokenString, &MemberstackJwtClaims{}, k.Keyfunc)
	return token, err
}

func NewMemberstackAdmin(o Options) MemberstackAdmin {
	if o.Issuer == "" {
		o.Issuer = ISSUER
	}
	if o.JWKSEndpoint == "" {
		o.JWKSEndpoint = JWKS_ENDPOINT
	}
	if o.HTTPTimeoutSeconds == 0 {
		o.HTTPTimeoutSeconds = 10
	}

	ma := MemberstackAdmin{Options: o}

	jwtParserOpts := []jwt.ParserOption{jwt.WithIssuer(o.Issuer)}
	if o.MemberstackAppId != "" {
		jwtParserOpts = append(jwtParserOpts, jwt.WithAudience(o.MemberstackAppId))
	}
	// TODO: Should my jwtParser also be a pointer?
	ma.jwtParser = *jwt.NewParser(jwtParserOpts...)

	ma.httpClient = http.Client{
		Timeout: time.Duration(o.HTTPTimeoutSeconds) * time.Second,
	}

	return ma
}

// GetMemberstackClaims is a utility function to correctly type the verified
// [jwt.Token.Claims] to Memberstack-specific JWT format
func GetMemberstackClaims(token *jwt.Token) *MemberstackJwtClaims {
	return token.Claims.(*MemberstackJwtClaims)
}
