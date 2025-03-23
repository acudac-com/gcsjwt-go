package gcsjwt_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/acudac-com/gcsjwt-go"
	"github.com/golang-jwt/jwt"
	"google.golang.org/grpc/metadata"
)

type Claims struct {
	Id  string `json:"id"`
	Exp int64  `json:"exp"`
}

func (c *Claims) Valid() error {
	if time.Now().Unix() > c.Exp {
		return jwt.NewValidationError("token is expired", jwt.ValidationErrorExpired)
	}
	return nil
}

var GcsJwt *gcsjwt.GcsJwt[*Claims]

func init() {
	var err error
	bucket := os.Getenv("KEYS_BUCKET")
	if GcsJwt, err = gcsjwt.New(bucket, func() *Claims { return &Claims{} }); err != nil {
		panic(err)
	}
}

func TestSignedJwt(t *testing.T) {
	ctx := context.Background()
	signedJwt, err := GcsJwt.Sign(ctx, &Claims{Id: "sadf", Exp: time.Now().Add(1 * time.Hour).Unix()})
	if err != nil {
		t.Errorf("creating signed jwt: %s", err)
	}
	publicKeys, err := GcsJwt.PublicKeys(ctx)
	if err != nil {
		t.Errorf("getting public keys: %s", err)
	}
	_ = publicKeys
	if claims, err := GcsJwt.Parse(ctx, signedJwt); err != nil {
		t.Errorf("validating signed jwt: %s", err)
	} else {
		t.Logf("claims: %v", claims)
	}

	newCtx := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", signedJwt))
	if claims, err := GcsJwt.ParseCtx(newCtx, "authorization"); err != nil {
		t.Errorf("validating signed jwt: %s", err)
	} else {
		t.Logf("claims: %v", claims)
	}
}

func TestInvalidJwt(t *testing.T) {
	ctx := context.Background()
	invalidJwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"
	if _, err := GcsJwt.Parse(ctx, invalidJwt); err == nil {
		t.Error("expected invalid jwt")
	}
}
