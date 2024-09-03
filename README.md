# go-memberstack-admin

[![build](https://github.com/f3ndot/go-memberstack-admin/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/f3ndot/go-memberstack-admin/actions/workflows/build.yml)

A [go](http://www.golang.org/) (or 'golang' for search engine friendliness) port of npm's [`@memberstack/admin`](https://www.npmjs.com/package/@memberstack/admin).

🐣 This is baby's first go module, so please: PR's welcome! 🙏

## Install

```bash
go get github.com/f3ndot/go-memberstack-admin
```

```go
import "github.com/f3ndot/go-memberstack-admin/admin"
```

## Usage

_Check out [cmd/examples](./cmd/examples/) for detailed usage_

### Verify Token

To verify a member's token:

```go
a := admin.NewMemberstackAdmin(admin.Options{
	MemberstackAppId: "app_clzb..."
})
token, err := a.VerifyToken("eyJhbGc...jEifQ")

fmt.Println("is valid:", token.Valid, ", error:", err)
fmt.Println("member ID:", admin.GetMemberstackClaims(token).MemberID)
```

Or via the examples:

```bash
go run cmd/examples/verify_token.go -aud app_clzb... eyJhbGc...jEifQ
```

## TODO List

- [x] Tests 😅
- [ ] Feature parity with `@memberstack/admin`
- [x] Add own errors for fetching JWKS failure conditions
- [ ] Improve JWKS lifecycle (refreshing)
- [ ] Maybe: use [lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) over MicahParks' keyfunc and jwkset
