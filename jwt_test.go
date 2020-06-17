package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var ctx context.Context

const jwtsecret = "s3cr3t4t3st"

func TestJWT(t *testing.T) {
	Init(jwtsecret)

	testCases := []struct {
		name string
		code int
		jwt  string
	}{
		{"No token returns StatusUnauthorized", http.StatusUnauthorized, ""},
		{"Invalid token returns StatusUnauthorized", http.StatusUnauthorized, "invalid"},
		{"Valid token returns StatusOK", http.StatusOK, getJWT(time.Now().Add(time.Minute * 1))},
		{"Expired token returns StatusUnauthorized", http.StatusUnauthorized, getJWT(time.Now().Add(time.Minute * -1))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			rc := httptest.NewRecorder()
			h := fmt.Sprintf("Bearer %s", tc.jwt)

			req.Header.Add("Authorization", h)

			http.Handler(JWT(getTestHandler())).ServeHTTP(rc, req)

			if rc.Code != tc.code {
				t.Errorf("Should return %s (%d). Not %s (%d)", http.StatusText(tc.code), tc.code, http.StatusText(rc.Code), rc.Code)
			}
		})
	}
}

func getJWT(exp time.Time) string {
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), &Payload{
		Name:           "Joe Doe",
		StandardClaims: jwt.StandardClaims{ExpiresAt: exp.Unix()},
	})

	tokenstring, err := token.SignedString([]byte(jwtsecret))
	if err != nil {
		log.Fatalln(err)
	}
	return tokenstring
}

func getTestHandler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}

	return http.HandlerFunc(fn)
}
