package gcsjwt_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/acudac-com/gcsjwt-go"
	"github.com/golang-jwt/jwt"
)

func init() {
	testBucket := os.Getenv("TEST_BUCKET")
	if testBucket == "" {
		panic("TEST_BUCKET env var not set")
	}
	if err := gcsjwt.Init(testBucket); err != nil {
		panic(err)
	}
}

func TestSignedJwt(t *testing.T) {
	ctx := context.Background()
	signedJwt, err := gcsjwt.SignedJwt(ctx, jwt.MapClaims{
		"sub":   "12345",
		"email": "johndoe@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Errorf("creating signed jwt: %s", err)
	}
	publicKeys, err := gcsjwt.PublicKeys(ctx)
	if err != nil {
		t.Errorf("getting public keys: %s", err)
	}
	t.Logf("signedJwt: %s", signedJwt)
	t.Logf("publicKeys: %v", publicKeys)
	if claims, err := gcsjwt.Validate(ctx, signedJwt); err != nil {
		t.Errorf("validating signed jwt: %s", err)
	} else {
		t.Logf("claims: %v", claims)
	}
}

func TestInvalidJwt(t *testing.T) {
	ctx := context.Background()
	invalidJwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"
	if _, err := gcsjwt.Validate(ctx, invalidJwt); err == nil {
		t.Error("expected invalid jwt")
	}
}
