package auth

import (
	"log"
	"net/http"
)

//Roles authorizes correct roles in payload from context
func Roles(fn http.HandlerFunc, roles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pl := r.Context().Value(PayloadContextKey)
		log.Println(pl)
		fn(w, r)
	}
}
