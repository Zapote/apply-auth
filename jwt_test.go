package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var ctx context.Context

const jwtsecret = "s3cr3t4t3st"

func TestJWT(t *testing.T) {
	Init(jwtsecret)

	testCases := []struct {
		name   string
		code   int
		jwt    string
		target string
	}{
		{"No token returns StatusUnauthorized", http.StatusUnauthorized, "", "/"},
		{"Invalid token returns StatusUnauthorized", http.StatusUnauthorized, "invalid", "/"},
		{"Valid token returns StatusOK", http.StatusOK, getJWT(time.Now().Add(time.Minute * 1)), "/"},
		{"Expired token returns StatusUnauthorized", http.StatusUnauthorized, getJWT(time.Now().Add(time.Minute * -1)), "/"},
		{"Allow anonymous does not require JWT", http.StatusOK, "", "http://example.com/allowed"},
	}

	AllowAnonymous("/allowed", "GET")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.target, nil)
			rc := httptest.NewRecorder()
			h := fmt.Sprintf("Bearer %s", tc.jwt)

			req.Header.Add("Authorization", h)

			handler := getTestHandler()
			jwtMiddleware := JWT(handler)

			http.Handler(jwtMiddleware).ServeHTTP(rc, req)

			if rc.Code != tc.code {
				t.Errorf("Should return %s (%d). Not %s (%d)", http.StatusText(tc.code), tc.code, http.StatusText(rc.Code), rc.Code)
			}
		})
	}
}

func getJWT(exp time.Time) string {
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), &Payload{
		Name: "Joe Doe",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
		},
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

func TestNewJWT_RoundTrip_Valid(t *testing.T) {
	secret = "test-secret-123" // set package-level secret used by NewJWT

	uid := uuid.New()
	now := time.Now()

	want := &Payload{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "issuer-abc",
			Subject:   "subject-xyz",
			Audience:  jwt.ClaimStrings{},
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "",
		},
		CustomerID:        "cust-001",
		CustomerShortName: "acme",
		UserID:            uid,
		Name:              "Jane Doe",
		Roles:             []string{"admin", "editor"},
	}

	// create token
	tokenStr, err := NewJWT(want)
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}
	if tokenStr == "" {
		t.Fatal("NewJWT() returned empty token string")
	}

	// parse token back using same secret
	gotClaims := &Payload{}
	token, err := jwt.ParseWithClaims(
		tokenStr,
		gotClaims,
		func(t *jwt.Token) (interface{}, error) {
			// ensure alg is what we expect
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(secret), nil
		},
		jwt.WithTimeFunc(func() time.Time { return now }),
		jwt.WithLeeway(2*time.Second),
	)
	if err != nil {
		t.Fatalf("ParseWithClaims() error = %v", err)
	}
	if !token.Valid {
		t.Fatalf("parsed token is not valid")
	}

	// field-by-field checks
	if gotClaims.Issuer != want.Issuer {
		t.Errorf("Issuer = %q, want %q", gotClaims.Issuer, want.Issuer)
	}
	if gotClaims.Subject != want.Subject {
		t.Errorf("Subject = %q, want %q", gotClaims.Subject, want.Subject)
	}
	if gotClaims.CustomerID != want.CustomerID {
		t.Errorf("CustomerID = %q, want %q", gotClaims.CustomerID, want.CustomerID)
	}
	if gotClaims.CustomerShortName != want.CustomerShortName {
		t.Errorf("CustomerShortName = %q, want %q", gotClaims.CustomerShortName, want.CustomerShortName)
	}
	if gotClaims.UserID != want.UserID {
		t.Errorf("UserID = %v, want %v", gotClaims.UserID, want.UserID)
	}
	if gotClaims.Name != want.Name {
		t.Errorf("Name = %q, want %q", gotClaims.Name, want.Name)
	}
	// compare roles
	if len(gotClaims.Roles) != len(want.Roles) {
		t.Fatalf("Roles length = %d, want %d", len(gotClaims.Roles), len(want.Roles))
	}
	for i := range want.Roles {
		if gotClaims.Roles[i] != want.Roles[i] {
			t.Errorf("Roles[%d] = %q, want %q", i, gotClaims.Roles[i], want.Roles[i])
		}
	}
	if gotClaims.ExpiresAt.Time != want.ExpiresAt.Time {
		t.Errorf("ExpiresAt = %v, want %v", gotClaims.ExpiresAt, want.ExpiresAt)
	}
	if gotClaims.IssuedAt == nil || want.IssuedAt == nil || gotClaims.IssuedAt.Time != want.IssuedAt.Time {
		t.Errorf("IssuedAt = %v, want %v", gotClaims.IssuedAt, want.IssuedAt)
	}
}

func TestParse_ExpiredToken(t *testing.T) {
	secret = "test-secret-expired"

	p := &Payload{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "issuer-abc",
			Subject:   "subject-xyz",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		},
		CustomerID: "cust-001",
	}

	tokenStr, err := NewJWT(p)
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	_, err = jwt.ParseWithClaims(
		tokenStr, &Payload{},
		func(t *jwt.Token) (any, error) { return []byte(secret), nil },
		jwt.WithIssuer("issuer-abc"),
		jwt.WithSubject("subject-xyz"),
	)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
}

func TestParse_WrongSecret(t *testing.T) {
	secret = "right-secret"

	p := &Payload{
		RegisteredClaims: jwt.RegisteredClaims{},
	}

	tokenStr, err := NewJWT(p)
	if err != nil {
		t.Fatalf("NewJWT() error = %v", err)
	}

	_, err = jwt.ParseWithClaims(
		tokenStr, &Payload{},
		func(t *jwt.Token) (any, error) { return []byte("wrong-secret"), nil },
	)
	if err == nil {
		t.Fatal("expected error with wrong secret")
	}
	if !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		t.Fatalf("want ErrTokenSignatureInvalid, got %v", err)
	}
}

func TestPayloadJSONTags_RegisteredClaims(t *testing.T) {
	uid := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	p := &Payload{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "issuer-abc",
			Subject:   "subject-xyz",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
		},
		CustomerID:        "cust-001",
		CustomerShortName: "acme",
		UserID:            uid,
		Name:              "Jane Doe",
		Roles:             []string{"admin", "editor"},
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("json.Marshal error = %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}

	wantKeys := []string{"iss", "sub", "exp", "iat", "cid", "csn", "uid", "name", "roles"}
	if len(m) != len(wantKeys) {
		t.Fatalf("JSON has %d keys, want %d. Got: %v", len(m), len(wantKeys), m)
	}
	for _, k := range wantKeys {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing key %q; got keys: %v", k, m)
		}
	}

	if m["iss"] != "issuer-abc" || m["sub"] != "subject-xyz" {
		t.Errorf("iss/sub mismatch: got iss=%v sub=%v", m["iss"], m["sub"])
	}

	expUnix := float64(now.Add(1 * time.Hour).Unix())
	iatUnix := float64(now.Unix())
	if m["exp"] != expUnix {
		t.Errorf("exp = %v, want %v", m["exp"], expUnix)
	}
	if m["iat"] != iatUnix {
		t.Errorf("iat = %v, want %v", m["iat"], iatUnix)
	}
	if got, ok := m["uid"].(string); !ok || got != uid.String() {
		t.Errorf("uid = %#v (type %T), want %q", m["uid"], m["uid"], uid.String())
	}
	roles, ok := m["roles"].([]any)
	if !ok || len(roles) != 2 {
		t.Fatalf("roles = %#v, want len 2", m["roles"])
	}
	if roles[0] != "admin" || roles[1] != "editor" {
		t.Errorf("roles content = %#v", roles)
	}
}
