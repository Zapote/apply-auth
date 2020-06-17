package auth

import (
	"context"
)

//ContextKey is string key for context
type ContextKey string

//PayloadContextKey is ContextKey for payload in context
const PayloadContextKey ContextKey = "auth.payload"

//GetPayload retrieves user payload from context
func GetPayload(ctx context.Context) *Payload {
	i := ctx.Value(PayloadContextKey)
	return i.(*Payload)
}
