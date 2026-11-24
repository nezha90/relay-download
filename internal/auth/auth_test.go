package auth

import (
	"testing"
	"time"
)

func TestJWTSignVerifyAndExpiry(t *testing.T) {
	secret := "super-secret-key"
	claims := AccessClaims{
		BNodeID:   "b1",
		ProjectID: "proj-a",
		ANodeID:   "a1",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
	}
	tok, err := SignAccessJWT(secret, claims)
	if err != nil {
		t.Fatalf("SignAccessJWT: %v", err)
	}
	got, err := VerifyAccessJWT(secret, tok)
	if err != nil {
		t.Fatalf("VerifyAccessJWT: %v", err)
	}
	if got.BNodeID != "b1" || got.ProjectID != "proj-a" || got.ANodeID != "a1" {
		t.Fatalf("unexpected claims: %+v", got)
	}
	if _, err := VerifyAccessJWT("wrong-secret", tok); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for wrong secret, got %v", err)
	}
	if _, err := VerifyAccessJWT(secret, tok+"tampered"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for tampered token, got %v", err)
	}

	expiredClaims := claims
	expiredClaims.ExpiresAt = time.Now().Add(-time.Second).Unix()
	expTok, _ := SignAccessJWT(secret, expiredClaims)
	if _, err := VerifyAccessJWT(secret, expTok); err != ErrExpiredToken {
		t.Fatalf("expected ErrExpiredToken, got %v", err)
	}
}
