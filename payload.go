package auth

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

//Payload model for JWT
type Payload struct {
	Issuer            string    `json:"iss"`
	Subject           string    `json:"sub"`
	CustomerID        string    `json:"cid"`
	CustomerShortName string    `json:"csn"`
	UserID            uuid.UUID `json:"uid"`
	Name              string    `json:"name"`
	Roles             []string  `json:"roles"`
	ExpiresAt         float64   `json:"exp"`
	IssuedAt          float64   `json:"iat"`
}

//Valid checks if payload is valid
func (p *Payload) Valid() error {
	if int64(p.ExpiresAt) < time.Now().Unix() {
		return fmt.Errorf("token expired")
	}

	return nil
}
