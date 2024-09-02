package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/f3ndot/go-memberstack-admin/admin"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <encoded token>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	a := admin.NewMemberstackAdmin(admin.Options{
		Audience: "add",
	})

	token, err := a.VerifyToken(os.Args[1])
	fmt.Println("is valid:", token.Valid, ", error:", err)

	// JWKS is cached from HTTP
	token, err = a.VerifyToken(os.Args[1])
	fmt.Println("is valid:", token.Valid, ", error:", err)
}
