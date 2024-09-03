package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/f3ndot/go-memberstack-admin/admin"
)

func main() {
	audPtr := flag.String("aud", "", "Verify the Memberstack App ID (ie JWT 'aud') the token should belong to")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Printf("Usage: %s [OPTIONS] <encoded token>\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(1)
	}

	a := admin.NewMemberstackAdmin(admin.Options{
		MemberstackAppId: *audPtr,
	})

	tokenString := flag.Arg(0)

	token, err := a.VerifyToken(tokenString)
	fmt.Println("token valid:", token.Valid, ", error:", err)

	// JWKS is cached from HTTP
	token, err = a.VerifyToken(tokenString)
	fmt.Println("token valid:", token.Valid, ", error:", err)

	if token.Valid {
		fmt.Println("token details (claims):")
	} else {
		fmt.Println("**INVALID** token details (claims):")
	}

	claims := admin.GetMemberstackClaims(token)
	claimsJson, _ := json.MarshalIndent(claims, "", "  ")
	fmt.Printf("%s\n\n", claimsJson)

	expTime, _ := claims.GetExpirationTime()
	fmt.Printf("  exp: %v\n", expTime)
	iatTime, _ := claims.GetIssuedAt()
	fmt.Printf("  iat: %v\n", iatTime)
}
