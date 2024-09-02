package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/f3ndot/go-memberstack-admin/admin"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	audPtr := flag.String("aud", "", "The audience (Memberstack App ID) of the token")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Printf("Usage: %s [OPTIONS] <encoded token>\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(1)
	}

	options := admin.Options{}
	if *audPtr != "" {
		options.Audience = *audPtr
	}
	a := admin.NewMemberstackAdmin(options)

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

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		for claim, rawValue := range claims {
			var value any
			switch claim {
			case "aud":
				v, err := claims.GetAudience()
				if err != nil {
					value = rawValue
				} else {
					value = v
				}
			case "exp":
				v, err := claims.GetExpirationTime()
				if err != nil {
					value = rawValue
				} else {
					value = v
				}
			case "iat":
				v, err := claims.GetIssuedAt()
				if err != nil {
					value = rawValue
				} else {
					value = v
				}
			case "iss":
				v, err := claims.GetIssuer()
				if err != nil {
					value = rawValue
				} else {
					value = v
				}
			case "sub":
				v, err := claims.GetSubject()
				if err != nil {
					value = rawValue
				} else {
					value = v
				}
			default:
				value = rawValue
			}
			fmt.Printf("  %s: %v\n", claim, value)
		}
	}
}
