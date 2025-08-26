package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Payload model for JWT
type Payload struct {
	jwt.RegisteredClaims
	CustomerID        string    `json:"cid"`
	CustomerShortName string    `json:"csn"`
	UserID            uuid.UUID `json:"uid"`
	Name              string    `json:"name"`
	Roles             []string  `json:"roles"`
}
