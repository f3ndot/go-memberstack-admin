package admin_test

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/f3ndot/go-memberstack-admin/admin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// Used for generating valid JWTs to test against
const TEST_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC1UUpQuuTYaGmB
y6Ul0wzS6vMzA5xQh4v5B8eGLMFKQ0iecQq8iai9GolpA+3zp9POwOyLWmTOIL6k
jWNUh93VMKr7osdJY5a83pAkeOLu2JSjoaCVvulbCDFeS2PBXUKzPyJ1mEav1hEW
QiHahfthiniQojXsA63wRLCYKUW8OmiO6YpLBi1eG6vcNPqh4/SsNBGEtNBonRNq
2KwzLzhaTEPma93OLTW54ETN538C2VEO7DooFBx75BXJS7LhI0biYVcKwJHlLA54
zydnYSc68At+ORMVulbwZxRp3Rt8ksv0piUX2DhzCE9qLyZSgo+tHY32f7uIU5ET
Cjhkt5frAgMBAAECggEAN1Gs5cKPrYL1pbcXFNo2UGeEea0BVQR17S21bzdaZajv
j/+XMfyh8cgV4mdjgvJSSgNMaBvVI5qT76p/grvNL40grZN1T+vFgqw4uBf1zL9h
Yice0nEjyzVNsqI3tjgY8I0zm0MxVdZu8iaNI5m7H4Ba1m3XG8HnoKWkZ1g4QXvh
A1+sRN7wjlBPZjCkcAnmmb27qwoaWHEmfAfgsYoKcFBgx0+2vOBSuXsRXGF9hntu
nCyvpZ4VaPlIOMmjuck0SaiBpF85RZSQ96df7k5/img2rFx6CdMd8d3JlyAPc6F+
v8QtZJjNJvhGJxLunaGfl8sOdacEp4YDqtNclEOV8QKBgQDdyw8+9hjOZCKs/csF
MuzCv/aw5eGnmcQbDaP4DPWfuW0ktEGoiB1fjO/B5UvXqHyCqfYCFzNEDQlzsLLd
jSiIxft0vxCXxxa7KrtyUc5g0ozJYcz+GXrcosD1VNy9xsdI10Z5Hy7tKu5YL8sj
SmRglPQhmypvV4pZ/RMCRO3XqQKBgQDRSCb24z60SzKm7hWg+Y5Q2N0+6Zk1Cnc3
+xpli42MDRYpYOPntE83szWWLzt9dhT97MY8IiqDw8TQZD12jaVetAdnwf2exOk8
qoZGlXwQaVabj0PWHiYa0TfQ5N2peHsqzsabgmICUbLIffB0QYmF65x08ErVXrPY
HRwHOxhfcwKBgQCCjBYyOgqJ2Tjr2AqaycnAK9uZbgXvb7uVLOc5hu9Aj5UliJAp
Ec0wQ7WPzFZi3sJC6qVpv5wmTwIkPXpam86jCt2ibx/mJoJDsrhYZrxyExxZIJ7X
ZcoCei3XeZbggVMllcjeXDNz19QoxiDsacpBawtziHBmzwEZTLPWnxnb2QKBgAUS
Ln+E+hv8RnntAvEnmt8yognIN0IlwsXEe9tCCmf+WS8ffeY7ZEABQ6cj9dkQZ2nP
tu32FfmjYL178FFTFVK6IgPNm4uhUdV6fE5xiNQM+WBDlG03xcyYjTWulgBpPvLG
l+Fkw2My/5YEFzN58w8fqmba+7U32ju+WNOEBw8pAoGAHK6kk6ZDHc9qvEC+UN92
cl4AKOaqGfAdoUJELUlDbUY8PKqJ4KDpor8qcucj9tlgcWf05eW13lle3KNflG9s
+D0CU3u2iFUNFSCwPc9tpP0yW1/EtPZQ9XpfXuaiuJID1yMKzFN1yxQWTNGoQBwm
F3xMVLn4lJrR9K6eJXJ8jag=
-----END PRIVATE KEY-----`

// JWKS-formatted equivalent of TEST_PRIVATE_KEY_PEM
const TEST_MOCK_JWKS_BODY = `{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "key_ops": [
        "sign",
        "verify"
      ],
      "alg": "RS256",
      "kid": "5b159001-e6a4-4b19-a9f0-7f0ea18f6f75",
      "d": "N1Gs5cKPrYL1pbcXFNo2UGeEea0BVQR17S21bzdaZajvj_-XMfyh8cgV4mdjgvJSSgNMaBvVI5qT76p_grvNL40grZN1T-vFgqw4uBf1zL9hYice0nEjyzVNsqI3tjgY8I0zm0MxVdZu8iaNI5m7H4Ba1m3XG8HnoKWkZ1g4QXvhA1-sRN7wjlBPZjCkcAnmmb27qwoaWHEmfAfgsYoKcFBgx0-2vOBSuXsRXGF9hntunCyvpZ4VaPlIOMmjuck0SaiBpF85RZSQ96df7k5_img2rFx6CdMd8d3JlyAPc6F-v8QtZJjNJvhGJxLunaGfl8sOdacEp4YDqtNclEOV8Q",
      "n": "tVFKULrk2GhpgculJdMM0urzMwOcUIeL-QfHhizBSkNInnEKvImovRqJaQPt86fTzsDsi1pkziC-pI1jVIfd1TCq-6LHSWOWvN6QJHji7tiUo6Gglb7pWwgxXktjwV1Csz8idZhGr9YRFkIh2oX7YYp4kKI17AOt8ESwmClFvDpojumKSwYtXhur3DT6oeP0rDQRhLTQaJ0TatisMy84WkxD5mvdzi01ueBEzed_AtlRDuw6KBQce-QVyUuy4SNG4mFXCsCR5SwOeM8nZ2EnOvALfjkTFbpW8GcUad0bfJLL9KYlF9g4cwhPai8mUoKPrR2N9n-7iFOREwo4ZLeX6w",
      "e": "AQAB",
      "p": "3csPPvYYzmQirP3LBTLswr_2sOXhp5nEGw2j-Az1n7ltJLRBqIgdX4zvweVL16h8gqn2AhczRA0Jc7Cy3Y0oiMX7dL8Ql8cWuyq7clHOYNKMyWHM_hl63KLA9VTcvcbHSNdGeR8u7SruWC_LI0pkYJT0IZsqb1eKWf0TAkTt16k",
      "q": "0Ugm9uM-tEsypu4VoPmOUNjdPumZNQp3N_saZYuNjA0WKWDj57RPN7M1li87fXYU_ezGPCIqg8PE0GQ9do2lXrQHZ8H9nsTpPKqGRpV8EGlWm49D1h4mGtE30OTdqXh7Ks7Gm4JiAlGyyH3wdEGJheucdPBK1V6z2B0cBzsYX3M",
      "dp": "gowWMjoKidk469gKmsnJwCvbmW4F72-7lSznOYbvQI-VJYiQKRHNMEO1j8xWYt7CQuqlab-cJk8CJD16WpvOowrdom8f5iaCQ7K4WGa8chMcWSCe12XKAnot13mW4IFTJZXI3lwzc9fUKMYg7GnKQWsLc4hwZs8BGUyz1p8Z29k",
      "dq": "BRIuf4T6G_xGee0C8Sea3zKiCcg3QiXCxcR720IKZ_5ZLx995jtkQAFDpyP12RBnac-27fYV-aNgvXvwUVMVUroiA82bi6FR1Xp8TnGI1Az5YEOUbTfFzJiNNa6WAGk-8saX4WTDYzL_lgQXM3nzDx-qZtr7tTfaO75Y04QHDyk",
      "qi": "HK6kk6ZDHc9qvEC-UN92cl4AKOaqGfAdoUJELUlDbUY8PKqJ4KDpor8qcucj9tlgcWf05eW13lle3KNflG9s-D0CU3u2iFUNFSCwPc9tpP0yW1_EtPZQ9XpfXuaiuJID1yMKzFN1yxQWTNGoQBwmF3xMVLn4lJrR9K6eJXJ8jag"
    }
  ]
}`

// The actual JWKS payload for Memberstack v2 as of 2024-02-09
const TEST_MOCK_MEMBERSTACK_JWKS_BODY = `{
  "keys": [
    {
      "kty": "RSA",
      "n": "oLJeKF8WPW-mqFxD5FUr_RHxwYty5-mZnOx9965ftfm20TqZL_svul3v8YGkbLgVnhl1kdzKd_6ViA4e1rsxpi9q4LLD93NY730znvnLvfnXQE6wHrWL4EHybsuaIIDWHCE4KqJY1tgInbr1bTQNRv12Qv5X4hXJYJ4-LLATbcAtQm3SuZ_nBrkAnh8F8qKhNOqnwSt2_v4RsWhH4gquXV_-fNGwKGZ6OHPB_TuJCa6ZmEG4tjuT1zbzKdswSUxsN7i9Whih67k-fVS8o25d89bm7EONDBm8FS-aV4PE8eLtNp2n2863fi6os1yq-8hyISRE1s2dOmPIF9UquN5h6Q",
      "e": "AQAB",
      "alg": "RS256",
      "use": "sig",
      "kid": "6f657ddbabfbfd95a4ed66c232411eaa6198d84c1bbd8a2a293b815fb4a99ab1"
    }
  ]
}`

// "Valid" but will definitely be expired
const TEST_VALID_MEMBERSTACK_JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjZmNjU3ZGRiYWJmYmZkOTVhNGVkNjZjMjMyNDExZWFhNjE5OGQ4NGMxYmJkOGEyYTI5M2I4MTVmYjRhOTlhYjEifQ.eyJpZCI6Im1lbV9zYl9jbTBsNnRnMTQwMGw0MHNzYTZ3cHgyMjRyIiwidHlwZSI6Im1lbWJlciIsImlzQWRtaW4iOnRydWUsImlhdCI6MTcyNTI5NzExNSwiZXhwIjoxNzI1MzAwNzE1LCJhdWQiOiJhcHBfY2x6dGJxcWpoMDA0NTBzczUxZHcwMHZ5NyIsImlzcyI6Imh0dHBzOi8vYXBpLm1lbWJlcnN0YWNrLmNvbSJ9.AxS7U-I1aeIPgN6H-hrAx-d8PW1b7plyP27ECPYAAYXjgycat-pHB6UUJn93TGQ_r3WBEVHGM9YTPHI4t3acIQ2yNLtTRkkOIMyEjizmjHKtMaDD1D5Itfh_A17UmANH8JUeO9auCJWx3hmZC29FBuCdu-pJZjd5Pz7hIzRC8s4_cC071ZHhSRUWqqSQQaDYEwkRmGGi4MnXPhWi2B-iAb6OupaqLDmg6klIRh8n2B0HbAtbHqr54Im0iXv_ch3NklhkpqJhqQ7uZkB-ZKZv_ydq0iu0sCdmdDinyGxdl7XhrsmAhd7vO_EXHNc6owHHNz_T_8rmJAP3DlG_rCjIoQ"

func TestVerifyToken(t *testing.T) {
	serverRequestsCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverRequestsCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(TEST_MOCK_JWKS_BODY))
	}))
	defer server.Close()

	rsaKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(TEST_PRIVATE_KEY_PEM))
	assert.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(time.Hour * -24)),
		Issuer:    admin.ISSUER,
		Audience:  jwt.ClaimStrings{"app_someid"},
	})
	token.Header["kid"] = "5b159001-e6a4-4b19-a9f0-7f0ea18f6f75" // must match TEST_MOCK_JWKS_BODY's
	signedJwt, err := token.SignedString(rsaKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, signedJwt)
	log.Printf("Generated test JWT %s", signedJwt)

	a := admin.NewMemberstackAdmin(admin.Options{
		JWKSEndpoint:     server.URL,
		MemberstackAppId: "app_someid",
	})
	token1, err1 := a.VerifyToken(signedJwt)
	token2, err2 := a.VerifyToken(signedJwt)

	assert.NoError(t, err1)
	assert.NoError(t, err2)

	assert.True(t, token1.Valid)
	assert.True(t, token2.Valid)

	assert.Equal(t, 1, serverRequestsCount, "JWKS HTTP server was called %d time(s)! Expected only once", serverRequestsCount)
}

func TestVerifyToken_ExpiredToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(TEST_MOCK_MEMBERSTACK_JWKS_BODY))
	}))
	defer server.Close()

	a := admin.NewMemberstackAdmin(admin.Options{
		JWKSEndpoint:     server.URL,
		MemberstackAppId: "app_clztbqqjh00450ss51dw00vy7",
	})

	token, err := a.VerifyToken(TEST_VALID_MEMBERSTACK_JWT)

	assert.ErrorIs(t, err, jwt.ErrTokenInvalidClaims)
	assert.ErrorIs(t, err, jwt.ErrTokenExpired)
	assert.False(t, token.Valid)
	assert.Equal(t, admin.GetMemberstackClaims(token).MemberID, "mem_sb_cm0l6tg1400l40ssa6wpx224r")
}

func TestVerifyToken_InvalidAudience(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(TEST_MOCK_MEMBERSTACK_JWKS_BODY))
	}))
	defer server.Close()

	a := admin.NewMemberstackAdmin(admin.Options{
		JWKSEndpoint:     server.URL,
		MemberstackAppId: "app_some-other-app-id",
	})

	token, err := a.VerifyToken(TEST_VALID_MEMBERSTACK_JWT)

	assert.ErrorIs(t, err, jwt.ErrTokenInvalidClaims)
	assert.ErrorIs(t, err, jwt.ErrTokenInvalidAudience)
	assert.False(t, token.Valid)
}

func TestVerifyToken_InvalidIssuer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(TEST_MOCK_MEMBERSTACK_JWKS_BODY))
	}))
	defer server.Close()

	a := admin.NewMemberstackAdmin(admin.Options{
		JWKSEndpoint:     server.URL,
		Issuer:           "something-else",
		MemberstackAppId: "app_clztbqqjh00450ss51dw00vy7",
	})

	token, err := a.VerifyToken(TEST_VALID_MEMBERSTACK_JWT)

	assert.ErrorIs(t, err, jwt.ErrTokenInvalidClaims)
	assert.ErrorIs(t, err, jwt.ErrTokenInvalidIssuer)
	assert.False(t, token.Valid)
}
