// Package middleware provides HTTP middleware shared across modules.
package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CtxKey for request-scoped values.
type CtxKey string

const (
	CtxUserID  CtxKey = "user_id"
	CtxIsStaff CtxKey = "is_staff"
)

// Recover wraps handler with panic recovery.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				http.Error(w, `{"code":1006,"message":"internal error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// CORSPermissive enables CORS for local development.
func CORSPermissive(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// TokenBucket is a simple in-memory rate limiter.
type TokenBucket struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    int
	window  time.Duration
}

type bucket struct {
	tokens    int
	resetAt   time.Time
}

// NewTokenBucket creates a rate limiter (tokens per window).
func NewTokenBucket(rate int, window time.Duration) *TokenBucket {
	return &TokenBucket{
		buckets: make(map[string]*bucket),
		rate:    rate,
		window:  window,
	}
}

// Allow reports whether a key is within limits.
func (tb *TokenBucket) Allow(key string) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	now := time.Now()
	b, ok := tb.buckets[key]
	if !ok || now.After(b.resetAt) {
		tb.buckets[key] = &bucket{tokens: tb.rate - 1, resetAt: now.Add(tb.window)}
		return true
	}
	if b.tokens > 0 {
		b.tokens--
		return true
	}
	return false
}

// RateLimit wraps a handler with token-bucket rate limiting.
func (tb *TokenBucket) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tb.Allow(r.RemoteAddr) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":    429,
				"message": "rate limit exceeded",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// VerifyHMAC checks the request body against an HMAC-SHA256 signature.
func VerifyHMAC(body []byte, signature, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expected))
}

// extractToken extracts a Bearer or Token token from the Authorization header.
func ExtractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if s, ok := strings.CutPrefix(auth, "Bearer "); ok {
		return s
	}
	if s, ok := strings.CutPrefix(auth, "Token "); ok {
		return s
	}
	return ""
}

// WithUser injects user info into the request context.
func WithUser(r *http.Request, userID uint64, isStaff bool) context.Context {
	ctx := r.Context()
	ctx = context.WithValue(ctx, CtxUserID, userID)
	ctx = context.WithValue(ctx, CtxIsStaff, isStaff)
	return ctx
}
