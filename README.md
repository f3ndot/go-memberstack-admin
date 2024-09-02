# go-memberstack-admin

A [go](http://www.golang.org/) (or 'golang' for search engine friendliness) port of npm's [`@memberstack/admin`](https://www.npmjs.com/package/@memberstack/admin).

This is baby's first go module, so please: PR's welcome!

## Usage (likely)

Verify a member's token:

```go
import "github.com/f3ndot/go-memberstack-admin/admin"

func main() {
  token, err = admin.VerifyToken("eyJhbGc...jEifQ")

  if err != nil; errors.Is(admin.ErrInvalidSignature) {
    log.Fatal(err)
  }

  log.Println("JWT verified token is ", token)
  // ...
}
```
