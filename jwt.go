package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

var secret string
var allowed []resource

//Init JWT middleware with jwtsecret
func Init(jwtsecret string) {
	secret = jwtsecret
}

//AllowAnonymous adds uri to anonymous allowed uris
func AllowAnonymous(uri string, method string) {
	allowed = append(allowed, resource{uri, method})
}

type resource struct {
	uri    string
	method string
}

//NewJWT creates a new JWT string
func NewJWT(p *Payload) (string, error) {
	k := []byte(secret)
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, p)
	return t.SignedString(k)
}

//JWT authorizes incoming request header Authorization
func JWT(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		url, _ := url.ParseRequestURI(r.RequestURI)
		method := r.Method
		for _, u := range allowed {
			if strings.HasPrefix(url.Path, u.uri) && u.method == method {
				next.ServeHTTP(w, r)
				return
			}
		}

		h := r.Header.Get("Authorization")
		h = strings.Replace(h, "Bearer ", "", -1)

		token, err := jwt.ParseWithClaims(h, &Payload{}, getPayload)

		if err != nil {
			log.Println(fmt.Sprintf("JWT: %s", err.Error()))
			response(w, 401, "Unauthorized")
			return
		}

		pl := token.Claims.(*Payload)

		ctx := context.WithValue(r.Context(), PayloadContextKey, pl)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func getPayload(t *jwt.Token) (interface{}, error) {
	if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
	}

	return []byte(secret), nil
}

func response(w http.ResponseWriter, httpStatusCode int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusCode)
	fmt.Fprintf(w, `{"result":%d,"error":%q}`, httpStatusCode, msg)
}
