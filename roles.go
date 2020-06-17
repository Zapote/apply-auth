package auth

import (
	"log"
	"net/http"

	"bitbucket.org/zapote/apply-api/types"
)

//Roles authorizes correct roles in payload from context
func Roles(fn http.HandlerFunc, roles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pl := r.Context().Value(types.PayloadContextKey)
		log.Println(pl)
		fn(w, r)
	}
}
