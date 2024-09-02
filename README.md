# go-memberstack-admin

A [go](http://www.golang.org/) (or 'golang' for search engine friendliness) port of npm's [`@memberstack/admin`](https://www.npmjs.com/package/@memberstack/admin).

This is baby's first go module, so please: PR's welcome!

## Usage (likely)

Verify a member's token:

```go
package main

import (
	"fmt"

  "github.com/f3ndot/go-memberstack-admin/admin"
)

func main() {
  a := admin.NewMemberstackAdmin()
  token, err := a.VerifyToken("eyJhbGc...jEifQ")

	fmt.Println("is valid:", token.Valid, ", error:", err)
}
```
