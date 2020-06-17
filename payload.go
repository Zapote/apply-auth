package auth

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

//Payload model for JWT
type Payload struct {
	jwt.StandardClaims
	CustomerID        string    `json:"cid"`
	CustomerShortName string    `json:"csn"`
	UserID            uuid.UUID `json:"uid"`
	Name              string    `json:"name"`
	Roles             []string  `json:"roles"`
}

//Valid checks if payload is valid
func (p *Payload) Valid() error {
	if int64(p.ExpiresAt) < time.Now().Unix() {
		return fmt.Errorf("token expired")
	}

	return nil
}
