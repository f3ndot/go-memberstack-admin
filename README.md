# go-memberstack-admin

A [go](http://www.golang.org/) (or 'golang' for search engine friendliness) port of npm's [`@memberstack/admin`](https://www.npmjs.com/package/@memberstack/admin).

This is baby's first go module, so please: PR's welcome!

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
```

Or via the examples:

```bash
go run cmd/examples/verify_token.go -aud app_clzb... eyJhbGc...jEifQ
```
